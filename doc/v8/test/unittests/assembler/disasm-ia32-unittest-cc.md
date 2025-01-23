Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Identify the Core Purpose:** The filename `disasm-ia32-unittest.cc` and the inclusion of headers like `src/diagnostics/disasm.h` and `src/diagnostics/disassembler.h` strongly suggest this code is related to disassembling IA-32 (x86) instructions. The `unittest` part indicates it's a unit test.

2. **Understand the Testing Framework:** The presence of `#include "testing/gtest/include/gtest/gtest.h"` tells us this code uses the Google Test framework. The `TEST_F` macro is a key indicator of a test fixture.

3. **Analyze the Test Fixture:** `using DisasmIa320Test = TestWithIsolate;` shows that the tests are part of a fixture named `DisasmIa320Test`, which inherits from `TestWithIsolate`. This likely provides a V8 `Isolate` (the core V8 runtime environment) for the tests.

4. **Examine the Test Case:** The `TEST_F(DisasmIa320Test, DisasmIa320)` macro defines a specific test case named `DisasmIa320` within the `DisasmIa320Test` fixture.

5. **Deconstruct the Test Logic:**  The core of the test involves the following steps:
    * **Setting up an Assembler:**  `Assembler assm(...)` creates an assembler object. This object will be used to generate machine code. The `ExternalAssemblerBuffer` indicates the generated code will be placed in the provided `buffer`.
    * **Generating IA-32 Instructions:** The numerous lines starting with `__` (which is a macro for `assm.`) are calls to the assembler to emit various IA-32 instructions. This is the *meat* of the test. The comments within this section ("Short immediate instructions", "This one caused crash", "All instructions that I can think of", etc.) provide hints about the test's intent – to cover a wide range of IA-32 instructions, potentially including those that previously caused issues.
    * **Creating a Code Object:**  `assm.GetCode(...)` retrieves the generated machine code from the assembler. This code is then encapsulated in a `Code` object.
    * **Optional Disassembly and Printing:** The `#ifdef OBJECT_PRINT` block suggests that, when enabled, the generated code is printed and then disassembled using `disasm::Disassembler::Disassemble`. This is crucial for *verifying* that the generated code is correct.

6. **Identify Key Functionality:** Based on the above, the main function of the code is to **test the IA-32 instruction encoding and decoding capabilities of the V8 engine**. It achieves this by:
    * Assembling a diverse set of IA-32 instructions.
    * Generating a `Code` object from the assembled instructions.
    * Optionally disassembling the generated code to verify its correctness.

7. **Address Specific Questions:** Now, let's address the specific questions in the prompt:

    * **Functionality:**  The code tests the IA-32 disassembler by generating various IA-32 instructions and verifying they can be correctly decoded.

    * **Torque:** The filename does *not* end in `.tq`, so it is *not* a Torque source file.

    * **JavaScript Relation:**  This code is indirectly related to JavaScript. V8 is a JavaScript engine, and it compiles JavaScript code into machine code. This unit test verifies that V8's internal assembler and disassembler for IA-32 are working correctly, which is essential for the proper execution of JavaScript on IA-32 architectures.

    * **JavaScript Example:**  To illustrate the connection, a simple JavaScript function might get compiled down to some of the IA-32 instructions tested here.

    * **Code Logic Inference:** The code's logic is straightforward: assemble a sequence of instructions and (optionally) disassemble them. We can infer the *input* to the disassembler (a buffer of bytes representing machine code) and the *output* (a human-readable representation of the instructions).

    * **Common Programming Errors:** The test itself doesn't directly demonstrate common *user* programming errors in JavaScript. However, it *indirectly* relates to errors that *could* occur in V8's code generation if the assembler or disassembler were buggy. A user wouldn't write this C++ code.

8. **Refine and Structure the Answer:** Finally, structure the analysis into a clear and concise answer, addressing each point of the prompt methodically. Use headings and bullet points to improve readability. Ensure the language is precise and avoids unnecessary jargon. For the JavaScript example, keep it simple and directly related to the assembly instructions. For the input/output, be explicit about what the disassembler is working with. For common errors, focus on the *indirect* connection to potential V8 bugs, not direct user errors.
## 功能列举

`v8/test/unittests/assembler/disasm-ia32-unittest.cc` 是 V8 JavaScript 引擎中一个用于测试 **IA-32 (x86) 架构反汇编器 (disassembler)** 功能的单元测试文件。

其主要功能是：

1. **生成各种 IA-32 汇编指令序列:** 代码中使用了 `Assembler` 类来生成大量的不同 IA-32 指令，涵盖了常见的算术运算、数据传输、控制流、位操作、浮点运算 (FPU)、SSE、AVX 等指令集。
2. **将生成的汇编指令编码到内存缓冲区:**  `Assembler` 将生成的汇编指令编码成机器码，并存储到预先分配的缓冲区 `buffer` 中。
3. **创建代码对象 (Code Object):** 将缓冲区中的机器码封装成 V8 内部的 `Code` 对象，这是 V8 中表示可执行代码的基本单元。
4. **（可选）反汇编生成的代码并打印:**  在 `#ifdef OBJECT_PRINT` 宏定义启用的情况下，代码会调用 V8 的反汇编器 (`disasm::Disassembler::Disassemble`) 将生成的机器码反汇编成可读的汇编代码，并将结果打印到标准输出。这部分主要用于人工检查反汇编结果是否正确。
5. **使用 Google Test 框架进行测试:**  代码使用 Google Test 框架 (`TEST_F`) 定义了一个名为 `DisasmIa320` 的测试用例，该用例会执行上述的汇编代码生成和可选的反汇编过程。这个测试的主要目的是确保 V8 的 IA-32 反汇编器能够正确地解析和显示各种不同的 IA-32 指令。

**总结来说，这个文件的核心功能是自动化地测试 V8 引擎中 IA-32 架构的反汇编功能是否正确可靠。**

## 关于文件后缀 `.tq`

`v8/test/unittests/assembler/disasm-ia32-unittest.cc` 的后缀是 `.cc`，表示它是一个 C++ 源文件。如果它的后缀是 `.tq`，那么它将是一个 V8 Torque 源代码文件。 Torque 是一种 V8 内部使用的类型化的中间语言，用于生成高效的 JavaScript 内置函数和运行时代码。

**因此，根据文件后缀，这个文件不是 V8 Torque 源代码。**

## 与 JavaScript 的关系

`v8/test/unittests/assembler/disasm-ia32-unittest.cc` 虽然是 C++ 代码，但它与 JavaScript 的功能有密切关系。

**关系说明:**

1. **V8 是 JavaScript 引擎:** V8 的核心功能是将 JavaScript 代码编译成机器码并在目标平台上执行。
2. **反汇编是理解机器码的关键:**  反汇编器可以将机器码转换回汇编语言，这对于理解 V8 如何将 JavaScript 代码编译成机器码，以及进行性能分析和调试至关重要。
3. **测试反汇编器的正确性至关重要:**  确保反汇编器能够正确地解析机器码，对于 V8 开发人员理解和调试生成的代码至关重要。如果反汇编器解析错误，可能会导致对代码行为的误解。

**JavaScript 举例说明:**

考虑以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

add(1, 2);
```

当 V8 执行这段代码时，`add` 函数会被编译成 IA-32 机器码（假设运行在 IA-32 架构上）。  `disasm-ia32-unittest.cc` 中测试的各种 IA-32 指令，例如 `add`、`mov`、`ret` 等，就有可能出现在 `add` 函数编译后的机器码中。

**例如，`add(1, 2)` 这个调用可能会导致 V8 生成类似的 IA-32 指令序列 (简化示例)：**

```assembly
push   ebp              ; 保存栈帧基址
mov    ebp, esp         ; 设置新的栈帧基址
mov    eax, [ebp+8]     ; 将参数 a (1) 移动到 eax 寄存器
add    eax, [ebp+12]    ; 将参数 b (2) 加到 eax 寄存器
pop    ebp              ; 恢复栈帧基址
ret                     ; 返回
```

`disasm-ia32-unittest.cc` 这样的测试用例确保了 V8 的反汇编器能够正确地将上述机器码转换回类似的可读汇编代码，帮助开发者理解 V8 的代码生成过程。

## 代码逻辑推理 (假设输入与输出)

**假设输入:**

代码会生成一系列 IA-32 机器码，这些机器码存储在 `buffer` 数组中。  例如，如果生成了以下两个指令：

* `mov eax, 12345`  (对应的机器码可能是 `B8 39 30 00 00`)
* `ret`           (对应的机器码可能是 `C3`)

那么 `buffer` 中对应的字节序列可能是 `B8 39 30 00 00 C3 ...`

**假设输出 (当 `#ifdef OBJECT_PRINT` 启用时):**

反汇编器会解析 `buffer` 中的字节，并生成相应的汇编代码字符串，输出到标准输出。 对于上述假设的输入，输出可能类似于：

```assembly
0x...: mov eax, 0x3039
0x...: ret
```

**更具体地，对于测试用例中的部分代码，例如：**

```c++
  __ add(eax, 12345678);
  __ add(eax, Immediate(12345678));
```

**假设输入 (相关的 `buffer` 内容):**  (实际机器码可能因 V8 版本和编译选项而异，这里仅为示例)

```
81 C0 76 1B 00 00  // add eax, 0x1b76
81 C0 76 1B 00 00  // add eax, 0x1b76 (Immediate 也会生成类似指令)
```

**假设输出 (反汇编结果):**

```assembly
0x...: add eax, 0x1b76
0x...: add eax, 0x1b76
```

**注意:** 实际的机器码和反汇编输出可能会更复杂，因为测试用例覆盖了大量的指令和寻址模式。  反汇编器的输出还会包含指令的地址等信息。

## 涉及用户常见的编程错误 (间接关系)

这个单元测试本身不涉及用户直接编写 JavaScript 代码时常犯的错误。 然而，它可以帮助发现和预防 V8 引擎内部的错误，这些错误 *可能* 会间接影响 JavaScript 程序的行为。

**例如，如果 V8 的 IA-32 反汇编器存在 bug，可能会导致：**

1. **调试困难:** 当开发者使用 V8 的调试工具查看 JavaScript 代码编译后的机器码时，如果反汇编结果不正确，可能会对程序的执行流程产生误解，增加调试难度。
2. **性能分析错误:**  如果反汇编器无法准确地解析指令，那么基于反汇编结果进行的性能分析可能会得出错误的结论，导致错误的优化方向。

**用户常见的 JavaScript 编程错误与此文件没有直接关系，例如：**

* **类型错误:**  在运行时对非预期类型的值进行操作，例如尝试对字符串进行数值运算。
* **作用域错误:**  在不应该访问的地方访问变量。
* **异步编程错误:**  例如回调地狱、promise 使用不当等。
* **内存泄漏:**  在 JavaScript 中通常由无意中保持对不再使用的对象的引用导致。

**总结:**  `disasm-ia32-unittest.cc` 的目标是保证 V8 内部工具的正确性，这间接地有助于提升 V8 引擎的稳定性和开发者体验，从而间接地减少用户在调试和分析 JavaScript 代码时遇到的问题。 它本身并不直接测试或涉及用户编写 JavaScript 代码时常见的错误。

### 提示词
```
这是目录为v8/test/unittests/assembler/disasm-ia32-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/assembler/disasm-ia32-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2011 the V8 project authors. All rights reserved.
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

#include "src/codegen/code-factory.h"
#include "src/codegen/macro-assembler.h"
#include "src/debug/debug.h"
#include "src/diagnostics/disasm.h"
#include "src/diagnostics/disassembler.h"
#include "src/execution/frames-inl.h"
#include "src/init/v8.h"
#include "src/utils/ostreams.h"
#include "test/unittests/test-utils.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace v8 {
namespace internal {

using DisasmIa320Test = TestWithIsolate;

#define __ assm.

TEST_F(DisasmIa320Test, DisasmIa320) {
  HandleScope scope(isolate());
  uint8_t buffer[8192];
  Assembler assm(AssemblerOptions{},
                 ExternalAssemblerBuffer(buffer, sizeof buffer));
  // Short immediate instructions
  __ adc(eax, 12345678);
  __ add(eax, Immediate(12345678));
  __ or_(eax, 12345678);
  __ sub(eax, Immediate(12345678));
  __ xor_(eax, 12345678);
  __ and_(eax, 12345678);
  Handle<FixedArray> foo =
      isolate()->factory()->NewFixedArray(10, AllocationType::kOld);
  __ cmp(eax, foo);

  // ---- This one caused crash
  __ mov(ebx, Operand(esp, ecx, times_2, 0));  // [esp+ecx*4]

  // ---- All instructions that I can think of
  __ add(edx, ebx);
  __ add(edx, Operand(12, RelocInfo::NO_INFO));
  __ add(edx, Operand(ebx, 0));
  __ add(edx, Operand(ebx, 16));
  __ add(edx, Operand(ebx, 1999));
  __ add(edx, Operand(ebx, -4));
  __ add(edx, Operand(ebx, -1999));
  __ add(edx, Operand(esp, 0));
  __ add(edx, Operand(esp, 16));
  __ add(edx, Operand(esp, 1999));
  __ add(edx, Operand(esp, -4));
  __ add(edx, Operand(esp, -1999));
  __ nop();
  __ add(esi, Operand(ecx, times_4, 0));
  __ add(esi, Operand(ecx, times_4, 24));
  __ add(esi, Operand(ecx, times_4, -4));
  __ add(esi, Operand(ecx, times_4, -1999));
  __ nop();
  __ add(edi, Operand(ebp, ecx, times_4, 0));
  __ add(edi, Operand(ebp, ecx, times_4, 12));
  __ add(edi, Operand(ebp, ecx, times_4, -8));
  __ add(edi, Operand(ebp, ecx, times_4, -3999));
  __ add(Operand(ebp, ecx, times_4, 12), Immediate(12));

  __ bswap(eax);

  __ nop();
  __ add(ebx, Immediate(12));
  __ nop();
  __ adc(edx, Operand(ebx));
  __ adc(ecx, 12);
  __ adc(ecx, 1000);
  __ nop();
  __ and_(edx, 3);
  __ and_(edx, Operand(esp, 4));
  __ cmp(edx, 3);
  __ cmp(edx, Operand(esp, 4));
  __ cmp(Operand(ebp, ecx, times_4, 0), Immediate(1000));
  Handle<FixedArray> foo2 =
      isolate()->factory()->NewFixedArray(10, AllocationType::kOld);
  __ cmp(ebx, foo2);
  __ cmpb(ebx, Operand(ebp, ecx, times_2, 0));
  __ cmpb(Operand(ebp, ecx, times_2, 0), ebx);
  __ or_(edx, 3);
  __ xor_(edx, 3);
  __ nop();
  __ cpuid();
  __ movsx_b(edx, ecx);
  __ movsx_w(edx, ecx);
  __ movzx_b(edx, ecx);
  __ movzx_w(edx, ecx);

  __ nop();
  __ imul(edx, ecx);
  __ shld(edx, ecx, 10);
  __ shld_cl(edx, ecx);
  __ shrd(edx, ecx, 10);
  __ shrd_cl(edx, ecx);
  __ bts(edx, ecx);
  __ bts(Operand(ebx, ecx, times_4, 0), ecx);
  __ nop();
  __ pushad();
  __ popad();
  __ pushfd();
  __ popfd();
  __ push(Immediate(12));
  __ push(Immediate(23456));
  __ push(ecx);
  __ push(esi);
  __ push(Operand(ebp, StandardFrameConstants::kFunctionOffset));
  __ push(Operand(ebx, ecx, times_4, 0));
  __ push(Operand(ebx, ecx, times_4, 0));
  __ push(Operand(ebx, ecx, times_4, 10000));
  __ pop(edx);
  __ pop(eax);
  __ pop(Operand(ebx, ecx, times_4, 0));
  __ nop();

  __ add(edx, Operand(esp, 16));
  __ add(edx, ecx);
  __ mov_b(edx, ecx);
  __ mov_b(ecx, 6);
  __ mov_b(Operand(ebx, ecx, times_4, 10000), 6);
  __ mov_b(Operand(esp, 16), edx);
  __ mov_w(edx, Operand(esp, 16));
  __ mov_w(Operand(esp, 16), edx);
  __ nop();
  __ movsx_w(edx, Operand(esp, 12));
  __ movsx_b(edx, Operand(esp, 12));
  __ movzx_w(edx, Operand(esp, 12));
  __ movzx_b(edx, Operand(esp, 12));
  __ nop();
  __ mov(edx, 1234567);
  __ mov(edx, Operand(esp, 12));
  __ mov(Operand(ebx, ecx, times_4, 10000), Immediate(12345));
  __ mov(Operand(ebx, ecx, times_4, 10000), edx);
  __ nop();
  __ dec_b(edx);
  __ dec_b(Operand(eax, 10));
  __ dec_b(Operand(ebx, ecx, times_4, 10000));
  __ dec(edx);
  __ cdq();

  __ nop();
  __ idiv(edx);
  __ idiv(Operand(edx, ecx, times_1, 1));
  __ idiv(Operand(esp, 12));
  __ div(edx);
  __ div(Operand(edx, ecx, times_1, 1));
  __ div(Operand(esp, 12));
  __ mul(edx);
  __ neg(edx);
  __ not_(edx);
  __ test(Operand(ebx, ecx, times_4, 10000), Immediate(123456));

  __ imul(edx, Operand(ebx, ecx, times_4, 10000));
  __ imul(edx, ecx, 12);
  __ imul(edx, Operand(edx, eax, times_2, 42), 8);
  __ imul(edx, ecx, 1000);
  __ imul(edx, Operand(ebx, ecx, times_4, 1), 9000);

  __ inc(edx);
  __ inc(Operand(ebx, ecx, times_4, 10000));
  __ push(Operand(ebx, ecx, times_4, 10000));
  __ pop(Operand(ebx, ecx, times_4, 10000));
  __ call(Operand(ebx, ecx, times_4, 10000));
  __ jmp(Operand(ebx, ecx, times_4, 10000));

  __ lea(edx, Operand(ebx, ecx, times_4, 10000));
  __ or_(edx, 12345);
  __ or_(edx, Operand(ebx, ecx, times_4, 10000));

  __ nop();

  __ rcl(edx, 1);
  __ rcl(edx, 7);
  __ rcr(edx, 1);
  __ rcr(edx, 7);
  __ ror(edx, 1);
  __ ror(edx, 6);
  __ ror_cl(edx);
  __ ror(Operand(ebx, ecx, times_4, 10000), 1);
  __ ror(Operand(ebx, ecx, times_4, 10000), 6);
  __ ror_cl(Operand(ebx, ecx, times_4, 10000));
  __ sar(edx, 1);
  __ sar(edx, 6);
  __ sar_cl(edx);
  __ sar(Operand(ebx, ecx, times_4, 10000), 1);
  __ sar(Operand(ebx, ecx, times_4, 10000), 6);
  __ sar_cl(Operand(ebx, ecx, times_4, 10000));
  __ sbb(edx, Operand(ebx, ecx, times_4, 10000));
  __ shl(edx, 1);
  __ shl(edx, 6);
  __ shl_cl(edx);
  __ shl(Operand(ebx, ecx, times_4, 10000), 1);
  __ shl(Operand(ebx, ecx, times_4, 10000), 6);
  __ shl_cl(Operand(ebx, ecx, times_4, 10000));
  __ shrd_cl(Operand(ebx, ecx, times_4, 10000), edx);
  __ shr(edx, 1);
  __ shr(edx, 7);
  __ shr_cl(edx);
  __ shr(Operand(ebx, ecx, times_4, 10000), 1);
  __ shr(Operand(ebx, ecx, times_4, 10000), 6);
  __ shr_cl(Operand(ebx, ecx, times_4, 10000));

  // Immediates

  __ adc(edx, 12345);

  __ add(ebx, Immediate(12));
  __ add(Operand(edx, ecx, times_4, 10000), Immediate(12));

  __ and_(ebx, 12345);

  __ cmp(ebx, 12345);
  __ cmp(ebx, Immediate(12));
  __ cmp(Operand(edx, ecx, times_4, 10000), Immediate(12));
  __ cmpb(eax, Immediate(100));

  __ or_(ebx, 12345);

  __ sub(ebx, Immediate(12));
  __ sub(Operand(edx, ecx, times_4, 10000), Immediate(12));

  __ xor_(ebx, 12345);

  __ imul(edx, ecx, 12);
  __ imul(edx, ecx, 1000);

  __ cld();
  __ rep_movs();
  __ rep_stos();
  __ stos();

  __ sub(edx, Operand(ebx, ecx, times_4, 10000));
  __ sub(edx, ebx);

  __ test(edx, Immediate(12345));
  __ test(edx, Operand(ebx, ecx, times_8, 10000));
  __ test(Operand(esi, edi, times_1, -20000000), Immediate(300000000));
  __ test_b(edx, Operand(ecx, ebx, times_2, 1000));
  __ test_b(Operand(eax, -20), Immediate(0x9A));
  __ nop();

  __ xor_(edx, 12345);
  __ xor_(edx, Operand(ebx, ecx, times_8, 10000));
  __ bts(Operand(ebx, ecx, times_8, 10000), edx);
  __ hlt();
  __ int3();
  __ ret(0);
  __ ret(8);

  // Calls

  Label L1, L2;
  __ bind(&L1);
  __ nop();
  __ call(&L1);
  __ call(&L2);
  __ nop();
  __ bind(&L2);
  __ call(Operand(ebx, ecx, times_4, 10000));
  __ nop();

  __ jmp(&L1);
  __ jmp(Operand(ebx, ecx, times_4, 10000));
  __ nop();

  Label Ljcc;
  __ nop();
  // long jumps
  __ j(overflow, &Ljcc);
  __ j(no_overflow, &Ljcc);
  __ j(below, &Ljcc);
  __ j(above_equal, &Ljcc);
  __ j(equal, &Ljcc);
  __ j(not_equal, &Ljcc);
  __ j(below_equal, &Ljcc);
  __ j(above, &Ljcc);
  __ j(sign, &Ljcc);
  __ j(not_sign, &Ljcc);
  __ j(parity_even, &Ljcc);
  __ j(parity_odd, &Ljcc);
  __ j(less, &Ljcc);
  __ j(greater_equal, &Ljcc);
  __ j(less_equal, &Ljcc);
  __ j(greater, &Ljcc);
  __ nop();
  __ bind(&Ljcc);
  // short jumps
  __ j(overflow, &Ljcc);
  __ j(no_overflow, &Ljcc);
  __ j(below, &Ljcc);
  __ j(above_equal, &Ljcc);
  __ j(equal, &Ljcc);
  __ j(not_equal, &Ljcc);
  __ j(below_equal, &Ljcc);
  __ j(above, &Ljcc);
  __ j(sign, &Ljcc);
  __ j(not_sign, &Ljcc);
  __ j(parity_even, &Ljcc);
  __ j(parity_odd, &Ljcc);
  __ j(less, &Ljcc);
  __ j(greater_equal, &Ljcc);
  __ j(less_equal, &Ljcc);
  __ j(greater, &Ljcc);

  // 0xD9 instructions
  __ nop();

  __ fld(1);
  __ fld1();
  __ fldz();
  __ fldpi();
  __ fabs();
  __ fchs();
  __ fprem();
  __ fprem1();
  __ fincstp();
  __ ftst();
  __ fxch(3);
  __ fld_s(Operand(ebx, ecx, times_4, 10000));
  __ fstp_s(Operand(ebx, ecx, times_4, 10000));
  __ ffree(3);
  __ fld_d(Operand(ebx, ecx, times_4, 10000));
  __ fstp_d(Operand(ebx, ecx, times_4, 10000));
  __ nop();

  __ fild_s(Operand(ebx, ecx, times_4, 10000));
  __ fistp_s(Operand(ebx, ecx, times_4, 10000));
  __ fild_d(Operand(ebx, ecx, times_4, 10000));
  __ fistp_d(Operand(ebx, ecx, times_4, 10000));
  __ fnstsw_ax();
  __ nop();
  __ fadd(3);
  __ fsub(3);
  __ fmul(3);
  __ fdiv(3);

  __ faddp(3);
  __ fsubp(3);
  __ fmulp(3);
  __ fdivp(3);
  __ fcompp();
  __ fwait();
  __ frndint();
  __ fninit();
  __ nop();

  // SSE instruction
  {
    // Move operation
    __ movaps(xmm0, xmm1);
    __ movups(xmm0, xmm1);
    __ movups(xmm0, Operand(edx, 4));
    __ movups(Operand(edx, 4), xmm0);
    __ shufps(xmm0, xmm0, 0x0);
    __ cvtsd2ss(xmm0, xmm1);
    __ cvtsd2ss(xmm0, Operand(ebx, ecx, times_4, 10000));
    __ movq(xmm0, Operand(edx, 4));

    __ movhlps(xmm0, xmm1);
    __ movlps(xmm0, Operand(ebx, ecx, times_4, 10000));
    __ movlps(Operand(ebx, ecx, times_4, 10000), xmm0);
    __ movhps(xmm0, Operand(ebx, ecx, times_4, 10000));
    __ movhps(Operand(ebx, ecx, times_4, 10000), xmm0);
    __ unpcklps(xmm0, xmm1);

    // logic operation
    __ andps(xmm0, xmm1);
    __ andps(xmm0, Operand(ebx, ecx, times_4, 10000));
    __ andnps(xmm0, xmm1);
    __ andnps(xmm0, Operand(ebx, ecx, times_4, 10000));
    __ orps(xmm0, xmm1);
    __ orps(xmm0, Operand(ebx, ecx, times_4, 10000));
    __ xorps(xmm0, xmm1);
    __ xorps(xmm0, Operand(ebx, ecx, times_4, 10000));

    // Arithmetic operation
    __ addss(xmm1, xmm0);
    __ addss(xmm1, Operand(ebx, ecx, times_4, 10000));
    __ mulss(xmm1, xmm0);
    __ mulss(xmm1, Operand(ebx, ecx, times_4, 10000));
    __ subss(xmm1, xmm0);
    __ subss(xmm1, Operand(ebx, ecx, times_4, 10000));
    __ divss(xmm1, xmm0);
    __ divss(xmm1, Operand(ebx, ecx, times_4, 10000));
    __ maxss(xmm1, xmm0);
    __ maxss(xmm1, Operand(ebx, ecx, times_4, 10000));
    __ minss(xmm1, xmm0);
    __ minss(xmm1, Operand(ebx, ecx, times_4, 10000));
    __ sqrtss(xmm1, xmm0);
    __ sqrtss(xmm1, Operand(ebx, ecx, times_4, 10000));
    __ addps(xmm1, xmm0);
    __ addps(xmm1, Operand(ebx, ecx, times_4, 10000));
    __ subps(xmm1, xmm0);
    __ subps(xmm1, Operand(ebx, ecx, times_4, 10000));
    __ mulps(xmm1, xmm0);
    __ mulps(xmm1, Operand(ebx, ecx, times_4, 10000));
    __ divps(xmm1, xmm0);
    __ divps(xmm1, Operand(ebx, ecx, times_4, 10000));
    __ minps(xmm1, xmm0);
    __ minps(xmm1, Operand(ebx, ecx, times_4, 10000));
    __ maxps(xmm1, xmm0);
    __ maxps(xmm1, Operand(ebx, ecx, times_4, 10000));
    __ rcpps(xmm1, xmm0);
    __ rcpps(xmm1, Operand(ebx, ecx, times_4, 10000));
    __ sqrtps(xmm1, xmm0);
    __ sqrtps(xmm1, Operand(ebx, ecx, times_4, 10000));
    __ rsqrtps(xmm1, xmm0);
    __ rsqrtps(xmm1, Operand(ebx, ecx, times_4, 10000));

    __ cmpeqps(xmm5, xmm1);
    __ cmpeqps(xmm5, Operand(ebx, ecx, times_4, 10000));
    __ cmpltps(xmm5, xmm1);
    __ cmpltps(xmm5, Operand(ebx, ecx, times_4, 10000));
    __ cmpleps(xmm5, xmm1);
    __ cmpleps(xmm5, Operand(ebx, ecx, times_4, 10000));
    __ cmpunordps(xmm5, xmm1);
    __ cmpunordps(xmm5, Operand(ebx, ecx, times_4, 10000));
    __ cmpneqps(xmm5, xmm1);
    __ cmpneqps(xmm5, Operand(ebx, ecx, times_4, 10000));

    __ ucomiss(xmm0, xmm1);
    __ ucomiss(xmm0, Operand(ebx, ecx, times_4, 10000));
  }
  {
    __ cvttss2si(edx, Operand(ebx, ecx, times_4, 10000));
    __ cvtsi2sd(xmm1, Operand(ebx, ecx, times_4, 10000));
    __ cvtss2sd(xmm1, Operand(ebx, ecx, times_4, 10000));
    __ cvtss2sd(xmm1, xmm0);
    __ cvtdq2ps(xmm1, xmm0);
    __ cvtdq2ps(xmm1, Operand(ebx, ecx, times_4, 10000));
    __ cvtdq2pd(xmm1, xmm0);
    __ cvtps2pd(xmm1, xmm0);
    __ cvtpd2ps(xmm1, xmm0);
    __ cvttps2dq(xmm1, xmm0);
    __ cvttps2dq(xmm1, Operand(ebx, ecx, times_4, 10000));
    __ cvttpd2dq(xmm1, xmm0);
    __ movsd(xmm1, Operand(ebx, ecx, times_4, 10000));
    __ movsd(Operand(ebx, ecx, times_4, 10000), xmm1);
    // 128 bit move instructions.
    __ movdqa(xmm0, Operand(ebx, ecx, times_4, 10000));
    __ movdqa(Operand(ebx, ecx, times_4, 10000), xmm0);
    __ movdqa(xmm1, xmm0);
    __ movdqu(xmm0, Operand(ebx, ecx, times_4, 10000));
    __ movdqu(Operand(ebx, ecx, times_4, 10000), xmm0);
    __ movdqu(xmm1, xmm0);

    __ movapd(xmm0, xmm1);
    __ movapd(xmm0, Operand(edx, 4));
    __ movupd(xmm0, Operand(edx, 4));

    __ movd(xmm0, edi);
    __ movd(xmm0, Operand(ebx, ecx, times_4, 10000));
    __ movd(eax, xmm1);
    __ movd(Operand(ebx, ecx, times_4, 10000), xmm1);

    __ ucomisd(xmm0, xmm1);
    __ cmpltsd(xmm0, xmm1);

    __ andpd(xmm0, xmm1);
    __ andpd(xmm0, Operand(ebx, ecx, times_4, 10000));
    __ andnpd(xmm0, xmm1);
    __ andnpd(xmm0, Operand(ebx, ecx, times_4, 10000));
    __ orpd(xmm0, xmm1);
    __ orpd(xmm0, Operand(ebx, ecx, times_4, 10000));
    __ xorpd(xmm0, xmm1);
    __ xorpd(xmm0, Operand(ebx, ecx, times_4, 10000));
    __ addpd(xmm1, xmm0);
    __ addpd(xmm1, Operand(ebx, ecx, times_4, 10000));
    __ subpd(xmm1, xmm0);
    __ subpd(xmm1, Operand(ebx, ecx, times_4, 10000));
    __ mulpd(xmm1, xmm0);
    __ mulpd(xmm1, Operand(ebx, ecx, times_4, 10000));
    __ divpd(xmm1, xmm0);
    __ divpd(xmm1, Operand(ebx, ecx, times_4, 10000));
    __ minpd(xmm1, xmm0);
    __ minpd(xmm1, Operand(ebx, ecx, times_4, 10000));
    __ maxpd(xmm1, xmm0);
    __ maxpd(xmm1, Operand(ebx, ecx, times_4, 10000));

    __ cmpeqpd(xmm5, xmm1);
    __ cmpeqpd(xmm5, Operand(ebx, ecx, times_4, 10000));
    __ cmpltpd(xmm5, xmm1);
    __ cmpltpd(xmm5, Operand(ebx, ecx, times_4, 10000));
    __ cmplepd(xmm5, xmm1);
    __ cmplepd(xmm5, Operand(ebx, ecx, times_4, 10000));
    __ cmpunordpd(xmm5, xmm1);
    __ cmpunordpd(xmm5, Operand(ebx, ecx, times_4, 10000));
    __ cmpneqpd(xmm5, xmm1);
    __ cmpneqpd(xmm5, Operand(ebx, ecx, times_4, 10000));

    __ psllw(xmm0, 17);
    __ pslld(xmm0, 17);
    __ psrlw(xmm0, 17);
    __ psrld(xmm0, 17);
    __ psraw(xmm0, 17);
    __ psrad(xmm0, 17);
    __ psllq(xmm0, 17);
    __ psrlq(xmm0, 17);

    __ pshufhw(xmm5, xmm1, 5);
    __ pshufhw(xmm5, Operand(edx, 4), 5);
    __ pshuflw(xmm5, xmm1, 5);
    __ pshuflw(xmm5, Operand(edx, 4), 5);
    __ pshufd(xmm5, xmm1, 5);
    __ pshufd(xmm5, Operand(edx, 4), 5);
    __ pinsrw(xmm5, edx, 5);
    __ pinsrw(xmm5, Operand(edx, 4), 5);

    __ movmskpd(edx, xmm5);
    __ movmskps(edx, xmm5);
    __ pmovmskb(edx, xmm5);

#define EMIT_SSE2_INSTR(instruction, notUsed1, notUsed2, notUsed3) \
  __ instruction(xmm5, xmm1);                                      \
  __ instruction(xmm5, Operand(edx, 4));

    SSE2_INSTRUCTION_LIST(EMIT_SSE2_INSTR)
    SSE2_INSTRUCTION_LIST_SD(EMIT_SSE2_INSTR)
#undef EMIT_SSE2_INSTR
  }

  // cmov.
  {
    __ cmov(overflow, eax, Operand(eax, 0));
    __ cmov(no_overflow, eax, Operand(eax, 1));
    __ cmov(below, eax, Operand(eax, 2));
    __ cmov(above_equal, eax, Operand(eax, 3));
    __ cmov(equal, eax, Operand(ebx, 0));
    __ cmov(not_equal, eax, Operand(ebx, 1));
    __ cmov(below_equal, eax, Operand(ebx, 2));
    __ cmov(above, eax, Operand(ebx, 3));
    __ cmov(sign, eax, Operand(ecx, 0));
    __ cmov(not_sign, eax, Operand(ecx, 1));
    __ cmov(parity_even, eax, Operand(ecx, 2));
    __ cmov(parity_odd, eax, Operand(ecx, 3));
    __ cmov(less, eax, Operand(edx, 0));
    __ cmov(greater_equal, eax, Operand(edx, 1));
    __ cmov(less_equal, eax, Operand(edx, 2));
    __ cmov(greater, eax, Operand(edx, 3));
  }

  {
    if (CpuFeatures::IsSupported(SSE3)) {
      CpuFeatureScope scope(&assm, SSE3);
      __ haddps(xmm1, xmm0);
      __ haddps(xmm1, Operand(ebx, ecx, times_4, 10000));
      __ movddup(xmm1, Operand(eax, 5));
      __ movddup(xmm1, xmm2);
      __ movshdup(xmm1, xmm2);
    }
  }

#define EMIT_SSE34_INSTR(instruction, notUsed1, notUsed2, notUsed3, notUsed4) \
  __ instruction(xmm5, xmm1);                                                 \
  __ instruction(xmm5, Operand(edx, 4));

  {
    if (CpuFeatures::IsSupported(SSSE3)) {
      CpuFeatureScope scope(&assm, SSSE3);
      SSSE3_INSTRUCTION_LIST(EMIT_SSE34_INSTR)
      SSSE3_UNOP_INSTRUCTION_LIST(EMIT_SSE34_INSTR)
      __ palignr(xmm5, xmm1, 5);
      __ palignr(xmm5, Operand(edx, 4), 5);
    }
  }

  {
    if (CpuFeatures::IsSupported(SSE4_1)) {
      CpuFeatureScope scope(&assm, SSE4_1);
      __ pblendw(xmm5, xmm1, 5);
      __ pblendw(xmm5, Operand(edx, 4), 5);
      __ pextrb(eax, xmm0, 1);
      __ pextrb(Operand(edx, 4), xmm0, 1);
      __ pextrw(eax, xmm0, 1);
      __ pextrw(Operand(edx, 4), xmm0, 1);
      __ pextrd(eax, xmm0, 1);
      __ pextrd(Operand(edx, 4), xmm0, 1);
      __ insertps(xmm1, xmm2, 0);
      __ insertps(xmm1, Operand(edx, 4), 0);
      __ pinsrb(xmm1, eax, 0);
      __ pinsrb(xmm1, Operand(edx, 4), 0);
      __ pinsrd(xmm1, eax, 0);
      __ pinsrd(xmm1, Operand(edx, 4), 0);
      __ extractps(eax, xmm1, 0);

      __ blendvps(xmm3, xmm1);
      __ blendvpd(xmm3, xmm1);
      __ pblendvb(xmm3, xmm1);

      SSE4_INSTRUCTION_LIST(EMIT_SSE34_INSTR)
      SSE4_RM_INSTRUCTION_LIST(EMIT_SSE34_INSTR)
    }
  }
#undef EMIT_SSE34_INSTR

  {
    if (CpuFeatures::IsSupported(SSE4_2)) {
      CpuFeatureScope scope(&assm, SSE4_2);
      __ pcmpgtq(xmm0, xmm1);
    }
  }

  // AVX instruction
  {
    if (CpuFeatures::IsSupported(AVX)) {
      CpuFeatureScope scope(&assm, AVX);
      __ vaddss(xmm0, xmm1, xmm2);
      __ vaddss(xmm0, xmm1, Operand(ebx, ecx, times_4, 10000));
      __ vmulss(xmm0, xmm1, xmm2);
      __ vmulss(xmm0, xmm1, Operand(ebx, ecx, times_4, 10000));
      __ vsubss(xmm0, xmm1, xmm2);
      __ vsubss(xmm0, xmm1, Operand(ebx, ecx, times_4, 10000));
      __ vdivss(xmm0, xmm1, xmm2);
      __ vdivss(xmm0, xmm1, Operand(ebx, ecx, times_4, 10000));
      __ vminss(xmm0, xmm1, xmm2);
      __ vminss(xmm0, xmm1, Operand(ebx, ecx, times_4, 10000));
      __ vmaxss(xmm0, xmm1, xmm2);
      __ vmaxss(xmm0, xmm1, Operand(ebx, ecx, times_4, 10000));
      __ vsqrtss(xmm0, xmm1, xmm2);
      __ vsqrtss(xmm0, xmm1, Operand(ebx, ecx, times_4, 10000));
      __ vucomisd(xmm0, xmm1);
      __ vucomisd(xmm0, Operand(ebx, ecx, times_4, 10000));
      __ vucomiss(xmm0, xmm1);
      __ vucomiss(xmm0, Operand(ebx, ecx, times_4, 10000));

      __ vandps(xmm0, xmm1, xmm2);
      __ vandps(xmm0, xmm1, Operand(ebx, ecx, times_4, 10000));
      __ vandnps(xmm0, xmm1, xmm2);
      __ vandnps(xmm0, xmm1, Operand(ebx, ecx, times_4, 10000));
      __ vorps(xmm0, xmm1, xmm2);
      __ vorps(xmm0, xmm1, Operand(ebx, ecx, times_4, 10000));
      __ vxorps(xmm0, xmm1, xmm2);
      __ vxorps(xmm0, xmm1, Operand(ebx, ecx, times_4, 10000));
      __ vaddps(xmm0, xmm1, xmm2);
      __ vaddps(xmm0, xmm1, Operand(ebx, ecx, times_4, 10000));
      __ vmulps(xmm0, xmm1, xmm2);
      __ vmulps(xmm0, xmm1, Operand(ebx, ecx, times_4, 10000));
      __ vsubps(xmm0, xmm1, xmm2);
      __ vsubps(xmm0, xmm1, Operand(ebx, ecx, times_4, 10000));
      __ vminps(xmm0, xmm1, xmm2);
      __ vminps(xmm0, xmm1, Operand(ebx, ecx, times_4, 10000));
      __ vdivps(xmm0, xmm1, xmm2);
      __ vdivps(xmm0, xmm1, Operand(ebx, ecx, times_4, 10000));
      __ vmaxps(xmm0, xmm1, xmm2);
      __ vmaxps(xmm0, xmm1, Operand(ebx, ecx, times_4, 10000));
      __ vrcpps(xmm1, xmm0);
      __ vrcpps(xmm1, Operand(ebx, ecx, times_4, 10000));
      __ vsqrtps(xmm1, xmm0);
      __ vsqrtps(xmm1, Operand(ebx, ecx, times_4, 10000));
      __ vrsqrtps(xmm1, xmm0);
      __ vrsqrtps(xmm1, Operand(ebx, ecx, times_4, 10000));
      __ vmovups(xmm0, xmm1);
      __ vmovups(xmm0, Operand(edx, 4));
      __ vmovaps(xmm0, xmm1);
      __ vmovapd(xmm0, xmm1);
      __ vmovapd(xmm0, Operand(ebx, ecx, times_4, 10000));
      __ vmovupd(xmm0, Operand(ebx, ecx, times_4, 10000));
      __ vshufps(xmm0, xmm1, xmm2, 3);
      __ vshufps(xmm0, xmm1, Operand(edx, 4), 3);
      __ vhaddps(xmm0, xmm1, xmm2);
      __ vhaddps(xmm0, xmm1, Operand(ebx, ecx, times_4, 10000));

      __ vmovhlps(xmm0, xmm1, xmm2);
      __ vmovlps(xmm0, xmm1, Operand(ebx, ecx, times_4, 10000));
      __ vmovlps(Operand(ebx, ecx, times_4, 10000), xmm0);
      __ vmovhps(xmm0, xmm1, Operand(ebx, ecx, times_4, 10000));
      __ vmovhps(Operand(ebx, ecx, times_4, 10000), xmm0);

      __ vcmpeqps(xmm5, xmm4, xmm1);
      __ vcmpeqps(xmm5, xmm4, Operand(ebx, ecx, times_4, 10000));
      __ vcmpltps(xmm5, xmm4, xmm1);
      __ vcmpltps(xmm5, xmm4, Operand(ebx, ecx, times_4, 10000));
      __ vcmpleps(xmm5, xmm4, xmm1);
      __ vcmpleps(xmm5, xmm4, Operand(ebx, ecx, times_4, 10000));
      __ vcmpunordps(xmm5, xmm4, xmm1);
      __ vcmpunordps(xmm5, xmm4, Operand(ebx, ecx, times_4, 10000));
      __ vcmpneqps(xmm5, xmm4, xmm1);
      __ vcmpneqps(xmm5, xmm4, Operand(ebx, ecx, times_4, 10000));
      __ vcmpgeps(xmm5, xmm4, xmm1);
      __ vcmpgeps(xmm5, xmm4, Operand(ebx, ecx, times_4, 10000));

      __ vandpd(xmm0, xmm1, xmm2);
      __ vandpd(xmm0, xmm1, Operand(ebx, ecx, times_4, 10000));
      __ vandnpd(xmm0, xmm1, xmm2);
      __ vandnpd(xmm0, xmm1, Operand(ebx, ecx, times_4, 10000));
      __ vorpd(xmm0, xmm1, xmm2);
      __ vorpd(xmm0, xmm1, Operand(ebx, ecx, times_4, 10000));
      __ vxorpd(xmm0, xmm1, xmm2);
      __ vxorpd(xmm0, xmm1, Operand(ebx, ecx, times_4, 10000));
      __ vaddpd(xmm0, xmm1, xmm2);
      __ vaddpd(xmm0, xmm1, Operand(ebx, ecx, times_4, 10000));
      __ vmulpd(xmm0, xmm1, xmm2);
      __ vmulpd(xmm0, xmm1, Operand(ebx, ecx, times_4, 10000));
      __ vsubpd(xmm0, xmm1, xmm2);
      __ vsubpd(xmm0, xmm1, Operand(ebx, ecx, times_4, 10000));
      __ vminpd(xmm0, xmm1, xmm2);
      __ vminpd(xmm0, xmm1, Operand(ebx, ecx, times_4, 10000));
      __ vdivpd(xmm0, xmm1, xmm2);
      __ vdivpd(xmm0, xmm1, Operand(ebx, ecx, times_4, 10000));
      __ vmaxpd(xmm0, xmm1, xmm2);
      __ vmaxpd(xmm0, xmm1, Operand(ebx, ecx, times_4, 10000));

      __ vcmpeqpd(xmm5, xmm4, xmm1);
      __ vcmpeqpd(xmm5, xmm4, Operand(ebx, ecx, times_4, 10000));
      __ vcmpltpd(xmm5, xmm4, xmm1);
      __ vcmpltpd(xmm5, xmm4, Operand(ebx, ecx, times_4, 10000));
      __ vcmplepd(xmm5, xmm4, xmm1);
      __ vcmplepd(xmm5, xmm4, Operand(ebx, ecx, times_4, 10000));
      __ vcmpunordpd(xmm5, xmm4, xmm1);
      __ vcmpunordpd(xmm5, xmm4, Operand(ebx, ecx, times_4, 10000));
      __ vcmpneqpd(xmm5, xmm4, xmm1);
      __ vcmpneqpd(xmm5, xmm4, Operand(ebx, ecx, times_4, 10000));

      __ vpsllw(xmm0, xmm7, 21);
      __ vpslld(xmm0, xmm7, 21);
      __ vpsllq(xmm0, xmm7, 21);
      __ vpsrlw(xmm0, xmm7, 21);
      __ vpsrld(xmm0, xmm7, 21);
      __ vpsrlq(xmm0, xmm7, 21);
      __ vpsraw(xmm0, xmm7, 21);
      __ vpsrad(xmm0, xmm7, 21);

      __ vpshufhw(xmm5, xmm1, 5);
      __ vpshufhw(xmm5, Operand(edx, 4), 5);
      __ vpshuflw(xmm5, xmm1, 5);
      __ vpshuflw(xmm5, Operand(edx, 4), 5);
      __ vpshufd(xmm5, xmm1, 5);
      __ vpshufd(xmm5, Operand(edx, 4), 5);
      __ vpblendw(xmm5, xmm1, xmm0, 5);
      __ vpblendw(xmm5, xmm1, Operand(edx, 4), 5);
      __ vpalignr(xmm5, xmm1, xmm0, 5);
      __ vpalignr(xmm5, xmm1, Operand(edx, 4), 5);
      __ vpextrb(eax, xmm0, 1);
      __ vpextrb(Operand(edx, 4), xmm0, 1);
      __ vpextrw(eax, xmm0, 1);
      __ vpextrw(Operand(edx, 4), xmm0, 1);
      __ vpextrd(eax, xmm0, 1);
      __ vpextrd(Operand(edx, 4), xmm0, 1);
      __ vinsertps(xmm0, xmm1, xmm2, 0);
      __ vinsertps(xmm0, xmm1, Operand(edx, 4), 0);
      __ vpinsrb(xmm0, xmm1, eax, 0);
      __ vpinsrb(xmm0, xmm1, Operand(edx, 4), 0);
      __ vpinsrw(xmm0, xmm1, eax, 0);
      __ vpinsrw(xmm0, xmm1, Operand(edx, 4), 0);
      __ vpinsrd(xmm0, xmm1, eax, 0);
      __ vpinsrd(xmm0, xmm1, Operand(edx, 4), 0);

      __ vblendvps(xmm3, xmm1, xmm4, xmm6);
      __ vblendvpd(xmm3, xmm1, xmm4, xmm6);
      __ vpblendvb(xmm3, xmm1, xmm4, xmm6);

      __ vcvtdq2ps(xmm1, xmm0);
      __ vcvtdq2ps(xmm1, Operand(ebx, ecx, times_4, 10000));
      __ vcvtdq2pd(xmm1, xmm0);
      __ vcvtps2pd(xmm1, xmm0);
      __ vcvtpd2ps(xmm1, xmm0);
      __ vcvttps2dq(xmm1, xmm0);
      __ vcvttps2dq(xmm1, Operand(ebx, ecx, times_4, 10000));
      __ vcvttpd2dq(xmm1, xmm0);

      __ vcvtsd2ss(xmm2, xmm3, Operand(ebx, ecx, times_4, 10000));
      __ vcvtsd2ss(xmm2, xmm3, xmm6);
      __ vcvtss2sd(xmm2, xmm3, Operand(ebx, ecx, times_1, 10000));
      __ vcvtss2sd(xmm2, xmm3, xmm6);
      __ vcvttsd2si(eax, Operand(ebx, ecx, times_4, 10000));
      __ vcvttsd2si(ebx, xmm6);
      __ vcvttss2si(eax, Operand(ebx, ecx, times_4, 10000));
      __ vcvttss2si(ebx, xmm6);

      __ vmovddup(xmm1, xmm2);
      __ vmovddup(xmm1, Operand(ebx, ecx, times_4, 10000));
      __ vmovshdup(xmm1, xmm2);
      __ vbroadcastss(xmm1, Operand(ebx, ecx, times_4, 10000));
      __ vmovdqa(xmm0, Operand(ebx, ecx, times_4, 10000));
      __ vmovdqa(xmm0, xmm7);
      __ vmovdqu(xmm0, Operand(ebx, ecx, times_4, 10000));
      __ vmovdqu(Operand(ebx, ecx, times_4, 10000), xmm0);
      __ vmovd(xmm0, edi);
      __ vmovd(xmm0, Operand(ebx, ecx, times_4, 10000));
      __ vmovd(eax, xmm1);
      __ vmovd(Operand(ebx, ecx, times_4, 10000), xmm1);

      __ vmovmskpd(edx, xmm5);
      __ vmovmskps(edx, xmm5);
      __ vpmovmskb(ebx, xmm1);

      __ vpcmpgtq(xmm0, xmm1, xmm2);

      __ vroundsd(xmm0, xmm3, xmm2, kRoundDown);
      __ vroundss(xmm0, xmm3, xmm2, kRoundDown);

#define EMIT_SSE2_AVXINSTR(instruction, notUsed1, notUsed2, notUsed3) \
  __ v##instruction(xmm7, xmm5, xmm1);                                \
  __ v##instruction(xmm7, xmm5, Operand(edx, 4));

      SSE2_INSTRUCTION_LIST(EMIT_SSE2_AVXINSTR)
      SSE2_INSTRUCTION_LIST_SD(EMIT_SSE2_AVXINSTR)
#undef EMIT_SSE2_AVXINSTR

#define EMIT_SSE34_AVXINSTR(instruction, notUsed1, notUsed2, notUsed3, \
                            notUsed4)                                  \
  __ v##instruction(xmm7, xmm5, xmm1);                                 \
  __ v##instruction(xmm7, xmm5, Operand(edx, 4));

      SSSE3_INSTRUCTION_LIST(EMIT_SSE34_AVXINSTR)
      SSE4_INSTRUCTION_LIST(EMIT_SSE34_AVXINSTR)
#undef EMIT_SSE34_AVXINSTR

#define EMIT_SSE4_RM_AVXINSTR(instruction, notUsed1, notUsed2, notUsed3, \
                              notUsed4)                                  \
  __ v##instruction(xmm5, xmm1);                                         \
  __ v##instruction(xmm5, Operand(edx, 4));

      SSSE3_UNOP_INSTRUCTION_LIST(EMIT_SSE4_RM_AVXINSTR)
      SSE4_RM_INSTRUCTION_LIST(EMIT_SSE4_RM_AVXINSTR)
#undef EMIT_SSE4_RM_AVXINSTR
    }
  }

  // AVX2 instructions.
  {
    if (CpuFeatures::IsSupported(AVX2)) {
      CpuFeatureScope scope(&assm, AVX2);
#define EMIT_AVX2_BROADCAST(instruction, notUsed1, notUsed2, notUsed3, \
                            notUsed4)                                  \
  __ instruction(xmm0, xmm1);                                          \
  __ instruction(xmm0, Operand(ebx, ecx, times_4, 10000));
      AVX2_BROADCAST_LIST(EMIT_AVX2_BROADCAST)
    }
  }

  // FMA3 instruction
  {
    if (CpuFeatures::IsSupported(FMA3)) {
      CpuFeatureScope scope(&assm, FMA3);
#define EMIT_FMA(instr, notUsed1, notUsed2, notUsed3, notUsed4, notUsed5, \
                 notUsed6)                                                \
  __ instr(xmm2, xmm1, xmm0);                                             \
  __ instr(xmm2, xmm1, Operand(ebx, ecx, times_4, 10000));
      FMA_INSTRUCTION_LIST(EMIT_FMA)
#undef EMIT_FMA
    }
  }

  // BMI1 instructions
  {
    if (CpuFeatures::IsSupported(BMI1)) {
      CpuFeatureScope scope(&assm, BMI1);
      __ andn(eax, ebx, ecx);
      __ andn(eax, ebx, Operand(ebx, ecx, times_4, 10000));
      __ bextr(eax, ebx, ecx);
      __ bextr(eax, Operand(ebx, ecx, times_4, 10000), ebx);
      __ blsi(eax, ebx);
      __ blsi(eax, Operand(ebx, ecx, times_4, 10000));
      __ blsmsk(eax, ebx);
      __ blsmsk(eax, Operand(ebx, ecx, times_4, 10000));
      __ blsr(eax, ebx);
      __ blsr(eax, Operand(ebx, ecx, times_4, 10000));
      __ tzcnt(eax, ebx);
      __ tzcnt(eax, Operand(ebx, ecx, times_4, 10000));
    }
  }

  // LZCNT instructions
  {
    if (CpuFeatures::IsSupported(LZCNT)) {
      CpuFeatureScope scope(&assm, LZCNT);
      __ lzcnt(eax, ebx);
      __ lzcnt(eax, Operand(ebx, ecx, times_4, 10000));
    }
  }

  // POPCNT instructions
  {
    if (CpuFeatures::IsSupported(POPCNT)) {
      CpuFeatureScope scope(&assm, POPCNT);
      __ popcnt(eax, ebx);
      __ popcnt(eax, Operand(ebx, ecx, times_4, 10000));
    }
  }

  // BMI2 instructions
  {
    if (CpuFeatures::IsSupported(BMI2)) {
      CpuFeatureScope scope(&assm, BMI2);
      __ bzhi(eax, ebx, ecx);
      __ bzhi(eax, Operand(ebx, ecx, times_4, 10000), ebx);
      __ mulx(eax, ebx, ecx);
      __ mulx(eax, ebx, Operand(ebx, ecx, times_4, 10000));
      __ pdep(eax, ebx, ecx);
      __ pdep(eax, ebx, Operand(ebx, ecx, times_4, 10000));
      __ pext(eax, ebx, ecx);
      __ pext(eax, ebx, Operand(ebx, ecx, times_4, 10000));
      __ sarx(eax, ebx, ecx);
      __ sarx(eax, Operand(ebx, ecx, times_4, 10000), ebx);
      __ shlx(eax, ebx, ecx);
      __ shlx(eax, Operand(ebx, ecx, times_4, 10000), ebx);
      __ shrx(eax, ebx, ecx);
      __ shrx(eax, Operand(ebx, ecx, times_4, 10000), ebx);
      __ rorx(eax, ebx, 31);
      __ rorx(eax, Operand(ebx, ecx, times_4, 10000), 31);
    }
  }

  // xadd.
  {
    __ xadd(Operand(eax, 8), eax);
    __ xadd_w(Operand(ebx, 8), eax);
    __ xadd_b(Operand(ebx, 8), eax);
  }
  // xchg.
  {
    __ xchg_b(eax, Operand(eax, 8));
    __ xchg_w(eax, Operand(ebx, 8));
    __ xchg(eax, eax);
    __ xchg(eax, ebx);
    __ xchg(ebx, ebx);
    __ xchg(ebx, Operand(esp, 12));
  }

  // cmpxchg.
  {
    __ cmpxchg_b(Operand(esp, 12), eax);
    __ cmpxchg_w(Operand(ebx, ecx, times_4, 10000), eax);
    __ cmpxchg(Operand(ebx, ecx, times_4, 10000), eax);
    __ cmpxchg(Operand(ebx, ecx, times_4, 10000), eax);
    __ cmpxchg8b(Operand(ebx, ecx, times_8, 10000));
  }

  // lock prefix.
  {
    __ lock();
    __ cmpxchg(Operand(esp, 12), ebx);

    __ lock();
    __ xchg_w(eax, Operand(ecx, 8));
  }

  // Nop instructions
  for (int i = 0; i < 16; i++) {
    __ Nop(i);
  }

  __ mfence();
  __ lfence();
  __ pause();
  __ ret(0);

  CodeDesc desc;
  assm.GetCode(isolate(), &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate(), desc, CodeKind::FOR_TESTING).Build();
  USE(code);
#ifdef OBJECT_PRINT
  StdoutStream os;
  Print(*code, os);
  Address begin = code->instruction_start();
  Address end = code->instruction_end();
  disasm::Disassembler::Disassemble(stdout, reinterpret_cast<uint8_t*>(begin),
                                    reinterpret_cast<uint8_t*>(end));
#endif
}

#undef __

}  // namespace internal
}  // namespace v8
```