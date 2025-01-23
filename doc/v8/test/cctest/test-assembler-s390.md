Response:
The user wants to understand the functionality of the provided C++ code. The code is a V8 test file for the s390 architecture's assembler.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Purpose:** The filename `test-assembler-s390.cc` and the `#include "src/codegen/s390/assembler-s390-inl.h"` clearly indicate this is a test suite for the s390 assembler within the V8 JavaScript engine.

2. **Analyze the Structure:** The code contains multiple `TEST()` macros. This is a common pattern in testing frameworks, where each `TEST()` function verifies a specific aspect of the code under test.

3. **Examine Individual Tests:** Go through each `TEST()` function and infer its purpose by looking at the assembler instructions being generated (`__ lhi`, `__ ar`, `__ b`, etc.). Recognize that these instructions are specific to the s390 architecture.

4. **Connect Tests to Functionality:**  Realize that these tests are designed to exercise different assembler instructions, addressing modes, and control flow mechanisms available on the s390 architecture. The tests are verifying the correctness of the assembler implementation.

5. **Check for Torque:** The prompt explicitly asks about `.tq` files. Observe that the provided filename ends in `.cc`, not `.tq`. Therefore, it's not a Torque file.

6. **Relate to JavaScript (if applicable):** The prompt asks about the connection to JavaScript. Since this is an assembler test, the connection is indirect. The assembler is used by the V8 engine to generate machine code that executes JavaScript. Think of it as the low-level foundation upon which JavaScript execution is built. Provide a simple JavaScript example to illustrate the kind of operations the assembler might be involved in at a lower level (arithmetic operations, function calls, etc.).

7. **Identify Logic and Assumptions:**  For tests that involve loops or conditional logic (like `TEST(1)`, `TEST(2)`, `TEST(4)`), analyze the generated assembly code to determine the expected input, the operations performed, and the expected output. This involves understanding the s390 instructions.

8. **Spot Common Programming Errors:**  Consider what kinds of errors could arise when working with assemblers or low-level code. Think about register usage, incorrect operand sizes, control flow issues, and the lack of automatic memory management. Provide illustrative examples.

9. **Address Specific Instructions:** If a test focuses on specific instructions (like `msrkc`, `brxh`, or vector instructions), mention those instructions explicitly and briefly explain their purpose. Note any CPU feature dependencies.

10. **Structure the Output:** Organize the information clearly using headings and bullet points to address each part of the prompt.

11. **Refine and Clarify:** Review the generated answer for clarity and accuracy. Ensure the language is precise and avoids jargon where possible. For example, explain that the assembler translates to *machine code*. Explain the role of `CodeDesc` and `Factory::CodeBuilder`.

**Self-Correction/Refinement During Thought Process:**

* **Initial thought:** Focus on each test individually and summarize its actions.
* **Refinement:**  Group the tests thematically (e.g., basic arithmetic, loops, floating-point, vector instructions) to provide a more coherent overview.
* **Initial thought:**  Simply state "it's an assembler test."
* **Refinement:** Explain *why* it's an assembler test and what that implies about its role in V8.
* **Initial thought:** Provide the literal assembly instructions as input/output examples.
* **Refinement:** Provide higher-level descriptions of the *intended* input and output of the tests, focusing on the logical behavior rather than the raw assembly.
* **Initial thought:**  Only mention obvious errors like syntax mistakes.
* **Refinement:** Include more conceptual errors related to low-level programming, such as incorrect register usage and memory management.

By following these steps and iteratively refining the analysis, we can generate a comprehensive and informative answer that addresses all aspects of the user's request.
`v8/test/cctest/test-assembler-s390.cc` 是 V8 JavaScript 引擎的测试文件，专门用于测试 s390 架构（IBM System/390 大型机）的 **汇编器 (Assembler)** 功能。

**功能概要:**

该文件的主要功能是编写一系列单元测试，用于验证 s390 汇编器的以下方面：

* **指令编码的正确性:** 测试各种 s390 汇编指令（如 `lhi`, `llilf`, `ar`, `b`, `lr`, `ahi`, `cfi`, `brc`, `mvc`,  以及更复杂的浮点和向量指令等）是否被正确地编码成机器码。
* **操作数处理:** 测试汇编器是否能正确处理不同类型的操作数，包括立即数、寄存器、内存操作数，以及带有位移和索引的内存操作数。
* **跳转和标签:** 测试条件跳转指令 (`beq`, `bne`, `ble`, `bgt`, `brc`, `brcl`, `brxh`, `brxhg`) 和标签 (`Label`) 的工作是否正确。
* **函数调用约定:** 虽然此文件中的测试更偏向于独立的指令序列，但它也间接测试了 V8 在 s390 上的基本函数调用约定，因为测试代码会生成可执行代码并调用。
* **特定 CPU 特性支持:**  一些测试（如 `TEST(10)` 和向量相关的测试）会检查特定的 s390 CPU 特性是否被支持 (`CpuFeatures::IsSupported`)，并据此执行不同的测试逻辑。
* **代码生成流程:** 测试 `Assembler` 类及其相关方法 (`GetCode`, `CodeDesc`, `Factory::CodeBuilder`) 生成可执行代码的过程。

**关于文件扩展名和 Torque:**

如果 `v8/test/cctest/test-assembler-s390.cc` 的文件扩展名是 `.tq`，那么它将是一个 **V8 Torque 源代码**文件。 Torque 是一种用于定义 V8 内部运行时函数的领域特定语言。  由于该文件的扩展名是 `.cc`，它是一个标准的 C++ 源文件。

**与 JavaScript 的关系:**

`v8/test/cctest/test-assembler-s390.cc` 中的代码与 JavaScript 的功能有着直接但底层的关系。  V8 引擎需要将 JavaScript 代码编译成可以在目标架构（这里是 s390）上执行的机器码。  `Assembler` 类就是负责生成这些机器码的关键组件。

当 V8 执行 JavaScript 代码时，它可能会使用到 `test-assembler-s390.cc` 中测试过的汇编指令来实现各种操作，例如：

* **算术运算:** JavaScript 中的加减乘除等运算会对应到汇编器的算术指令，例如 `ar` (add register), `sr` (subtract register), `mr_z` (multiply register), `dr` (divide register)。
* **变量访问:** 访问 JavaScript 变量可能涉及到从内存中加载数据 (`l`, `lg`, `llilf`) 或将数据存储到内存 (`st`, `stg`, `stm`)。
* **控制流:** JavaScript 的 `if` 语句、循环等控制结构会被翻译成汇编器的条件跳转指令 (`beq`, `bne`, `b`).
* **函数调用:**  JavaScript 函数的调用会涉及到设置栈帧、传递参数、跳转到函数地址等汇编操作。
* **对象操作:**  操作 JavaScript 对象可能涉及到更复杂的汇编指令序列，用于访问对象的属性、调用方法等。

**JavaScript 示例:**

以下是一些简单的 JavaScript 示例，它们在底层可能会使用到 `test-assembler-s390.cc` 中测试的 s390 汇编指令：

```javascript
// 简单的加法运算
function add(a, b) {
  return a + b; // 底层可能使用 'ar' 指令
}

// 条件判断
function isPositive(x) {
  if (x > 0) { // 底层可能使用比较指令和条件跳转指令
    return true;
  } else {
    return false;
  }
}

// 循环
function sum(n) {
  let result = 0;
  for (let i = 1; i <= n; i++) { // 底层可能使用循环控制指令和加法指令
    result += i;
  }
  return result;
}
```

**代码逻辑推理、假设输入与输出:**

让我们分析 `TEST(0)` 的代码逻辑：

```c++
TEST(0) {
  // ... 省略初始化代码 ...

  Assembler assm(AssemblerOptions{});

  __ lhi(r1, Operand(3));    // 将立即数 3 加载到寄存器 r1 的低半字
  __ llilf(r2, Operand(4));  // 将立即数 4 加载到寄存器 r2
  __ lgr(r2, r2);            // 将 r2 的内容复制到 r2 (实际上是冗余的，但用于测试指令)
  __ ar(r2, r1);             // 将 r1 的内容加到 r2
  __ b(r14);                 // 跳转到返回地址 (r14)

  // ... 省略代码生成和执行部分 ...
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  intptr_t res = reinterpret_cast<intptr_t>(f.Call(3, 4, 0, 0, 0));
  ::printf("f() = %" V8PRIxPTR "\n", res);
  CHECK_EQ(7, static_cast<int>(res));
}
```

**假设输入:** `f.Call(3, 4, 0, 0, 0)`，其中隐含地将 3 传递到第一个参数位置，4 传递到第二个参数位置 (在这个简单的测试中，参数传递的细节可能被简化)。  注意，这段汇编代码本身并没有直接使用传入的参数，而是使用了硬编码的立即数。

**代码逻辑推理:**

1. `__ lhi(r1, Operand(3));`: 将立即数 3 加载到寄存器 `r1` 的低半字。
2. `__ llilf(r2, Operand(4));`: 将立即数 4 加载到寄存器 `r2`。
3. `__ lgr(r2, r2);`: 将寄存器 `r2` 的内容复制到 `r2`，这是一个空操作。
4. `__ ar(r2, r1);`: 将寄存器 `r1` 的内容 (3) 加到寄存器 `r2` 的内容 (4)，结果为 7，并存储回 `r2`。
5. `__ b(r14);`: 跳转到返回地址，通常寄存器 `r2` 会被用作返回值。

**输出:**  寄存器 `r2` 的值将为 7。`CHECK_EQ(7, static_cast<int>(res));` 断言执行结果是否为 7。

**用户常见的编程错误 (在编写汇编代码或类似底层代码时):**

1. **寄存器使用错误:**  错误地使用了某个寄存器，导致数据被意外覆盖或使用了错误的值。
   ```c++
   // 错误示例：假设 r1 中存储了重要的中间结果
   __ lhi(r1, Operand(3));
   __ ar(r2, r3); // 正确的操作
   __ lhi(r1, Operand(5)); // 错误：r1 的值被覆盖了
   ```

2. **操作数类型或大小不匹配:**  使用了不兼容的操作数类型或大小，例如将一个 4 字节的值加载到只能存储 2 字节的寄存器中（虽然 s390 的寄存器通常是 64 位的，但有些指令操作的是其子部分）。
   ```c++
   // 错误示例：尝试将一个完整的 4 字节立即数加载到 lhi (load half immediate) 中
   // __ lhi(r1, Operand(0x12345678)); // 这通常是不允许的，应该使用 iilf 或类似的指令
   ```

3. **跳转目标错误或缺少跳转:**  条件跳转的条件设置不正确，或者跳转到了错误的标签，导致程序流程错误。忘记添加必要的跳转指令也会导致代码执行顺序混乱。
   ```c++
   // 错误示例：条件判断逻辑错误
   Label skip;
   __ chi(r2, Operand(10));
   // 假设这里应该有一个 bge (&skip); 但被遗漏了
   __ ar(r2, r1); // 这段代码会无条件执行

   __ bind(&skip);
   ```

4. **栈操作错误:**  在函数调用或局部变量管理中，错误地操作栈指针（例如 `sp`），导致栈溢出或数据损坏。
   ```c++
   // 错误示例：忘记调整栈指针
   __ lay(sp, MemOperand(sp, -4)); // 分配栈空间
   // ... 使用栈空间 ...
   // 忘记 __ lay(sp, MemOperand(sp, 4)); // 释放栈空间，可能导致栈溢出
   __ b(r14);
   ```

5. **内存访问错误:**  访问了无效的内存地址，例如空指针解引用或越界访问数组。  在汇编层面，这可能表现为使用了错误的基址寄存器或偏移量。
   ```c++
   // 错误示例：使用未初始化的寄存器作为内存地址
   // __ l(r2, MemOperand(r3)); // 如果 r3 没有被正确初始化，会导致错误
   ```

6. **忽略 CPU 特性:** 尝试使用目标 CPU 不支持的指令，导致程序崩溃或产生不可预测的结果。例如，在没有 `VECTOR_FACILITY` 的 CPU 上使用向量指令。

这些错误在汇编代码中尤其难以调试，因为没有高级语言提供的类型检查和内存管理。 `test-assembler-s390.cc` 中的单元测试正是为了帮助开发者在开发 V8 引擎时避免这些底层的编程错误。

### 提示词
```
这是目录为v8/test/cctest/test-assembler-s390.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-s390.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```
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
```