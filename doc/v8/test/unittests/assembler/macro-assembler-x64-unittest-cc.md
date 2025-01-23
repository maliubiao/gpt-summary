Response:
Let's break down the thought process for analyzing the provided C++ unittest code.

**1. Initial Understanding - The Big Picture**

The filename `macro-assembler-x64-unittest.cc` immediately tells us this is a unit test file specifically for the x64 macro assembler in V8. The presence of `#include "src/codegen/macro-assembler.h"` confirms this. The "unittest" part means it's designed to test individual units of functionality in isolation.

**2. Core Functionality - What is being tested?**

The core of a macro assembler is to generate machine code. Therefore, this test file is likely testing the various instructions and features provided by the `MacroAssembler` class for the x64 architecture. This involves:

* **Generating x64 instructions:**  The `__` macro suggests calls to the `MacroAssembler`'s methods for emitting instructions.
* **Executing generated code:**  The code allocates a buffer, uses the `MacroAssembler` to write code into it, makes the buffer executable, and then calls the generated code.
* **Verifying results:** The tests assert specific outcomes based on the generated code's execution.

**3. Examining Key Sections - Identifying Specific Tests**

Scanning through the code, we see several `TEST_F` blocks. Each `TEST_F` represents an individual test case. Let's look at some examples and how we'd analyze them:

* **`TEST_F(MacroAssemblerX64Test, TestHardAbort)`:**  The name suggests this tests the `Abort` functionality. The code calls `__ Abort(AbortReason::kNoReason);`. The `ASSERT_DEATH_IF_SUPPORTED` confirms that the test expects the program to terminate with an "abort: no reason" message.

* **`TEST_F(MacroAssemblerX64Test, TestCheck)`:** Similar to the above, this likely tests the `Check` macro, which conditionally aborts. The code compares a register with an argument and calls `__ Check(Condition::not_equal, AbortReason::kNoReason);`. The test then calls the generated function with values that should pass and one that should trigger the abort.

* **`TEST_F(MacroAssemblerX64Test, Smi)`:** The name "Smi" indicates this test focuses on Small Integers, a specific type in V8. The code iterates through various integer values and checks if they are valid Smis and how they are represented.

* **`TEST_F(MacroAssemblerX64Test, SmiMove)`:** This test moves Smi values directly into registers using `__ Move`. It verifies that the moved value is correct.

* **`TEST_F(MacroAssemblerX64Test, SmiCompare)`:** This test focuses on comparing Smi values using `__ SmiCompare`. It checks the results for different comparison scenarios (less than, greater than, equal to).

* **`TEST_F(MacroAssemblerX64Test, SmiTag)`:** This tests the `__ SmiTag` instruction, which converts an integer to its Smi representation.

* **`TEST_F(MacroAssemblerX64Test, SmiCheck)`:** This tests the `CheckSmi` method, which verifies if a value is a valid Smi.

* **`TEST_F(MacroAssemblerX64Test, SmiIndex)`:** This test seems to be about calculating memory addresses based on Smi values, likely related to array indexing.

* **`TEST_F(MacroAssemblerX64Test, EmbeddedObj)`:**  This test specifically deals with how V8 embeds objects (both compressed and full) into the generated code and how these are handled during garbage collection.

* **`TEST_F(MacroAssemblerX64Test, OperandOffset)`:** This test is about verifying the correctness of memory access using different operand addressing modes with various offsets, especially concerning stack manipulation.

* **`TEST_F(MacroAssemblerX64Test, ...)` (Float16x8Abs, Float16x8Neg, Float32x4Abs, Float32x4Neg, Float64x2Abs):** These tests are focused on SIMD (Single Instruction, Multiple Data) instructions for floating-point numbers, specifically the `Abs` (absolute value) and `Neg` (negation) operations for different vector sizes (8 half-precision floats, 4 single-precision floats, 2 double-precision floats).

**4. Considering the Instructions**

The code heavily uses the `__` macro, which is a shorthand for calling methods on the `MacroAssembler` object. By looking at the instructions used (e.g., `movl`, `cmpl`, `j(not_equal)`, `pushq`, `popq`, `xorq`, `shlq`, `cmp_tagged`, `SmiTag`, `CheckSmi`, `Movups`, `Absph`, `Negph`, `Movss`, `Absps`, `Negps`, `Movsd`, `Absd`), we can infer the types of operations being tested:

* **Data movement:** `movl`, `movq`, `Move`, `Movups`, `Movss`, `Movsd`
* **Arithmetic/Logical:** `xorq`, `shlq`
* **Comparison:** `cmpl`, `cmpq`, `cmp_tagged`, `Ucomiss`
* **Control flow:** `j(not_equal)`, `ret`, `bind`
* **Stack manipulation:** `pushq`, `popq`, `AllocateStackSpace`
* **Specific V8 operations:** `SmiTag`, `CheckSmi`, `SmiCompare`
* **SIMD operations:** `Absph`, `Negph`, `Absps`, `Negps`, `Absd`

**5. Answering Specific Questions (Internal Monologue)**

* **Functionality:**  The core functionality is testing the x64 macro assembler.
* **Torque:** The filename ends in `.cc`, not `.tq`, so it's not a Torque file.
* **JavaScript Relation:** The assembler is used by the V8 JavaScript engine to generate machine code for executing JavaScript. While this file doesn't *directly* contain JavaScript, the tested instructions are the building blocks for implementing JavaScript features.
* **JavaScript Example:**  Thinking about `SmiTag` and `SmiCompare`, these relate to how JavaScript handles small integers internally. A simple JavaScript example would be `let x = 5; let y = 10; if (x < y) { ... }`. V8 would use instructions similar to those tested to perform this comparison.
* **Code Logic Inference:**  The `TestCheck` function provides a good example.
    * **Assumption:** The generated code receives an integer as its first argument.
    * **Input 0:** `f.Call(0)` -> `kCArgRegs[0]` (RSI) will be 0. The `Check` will pass because 0 is not equal to 17. **Output:** No abort.
    * **Input 18:** `f.Call(18)` -> `kCArgRegs[0]` will be 18. The `Check` will pass. **Output:** No abort.
    * **Input 17:** `f.Call(17)` -> `kCArgRegs[0]` will be 17. The `Check` will fail because 17 is equal to 17. **Output:** Program aborts.
* **Common Programming Errors:**  While not directly testing user errors, understanding how assembly works helps avoid errors in higher-level code. For example, incorrect memory addressing (tested in `OperandOffset`) can lead to crashes or unexpected behavior in any language. Not handling integer types correctly (related to Smi tests) can lead to performance issues or unexpected results in JavaScript.
* **Summary:**  The file tests the core functionalities of the x64 macro assembler in V8, including instruction emission for various data types (Smis, floats), control flow, and memory access.

**6. Structuring the Answer**

Finally, the information gathered is organized into a clear and concise answer, addressing each part of the prompt systematically. This involves summarizing the overall function, addressing the filename extension, providing the JavaScript relation with an example, explaining the code logic with assumptions, highlighting potential programming errors, and summarizing the functionalities covered in the provided code snippet (part 1).好的，让我们来分析一下这个V8的单元测试源代码文件 `v8/test/unittests/assembler/macro-assembler-x64-unittest.cc` 的功能。

**核心功能归纳：**

这个C++源代码文件是 V8 JavaScript 引擎的一部分，它专门用于 **单元测试 x64 架构下的宏汇编器 (MacroAssembler)**。  其主要目的是验证 `MacroAssembler` 类在生成 x64 机器码时的正确性和功能性。

**具体功能点：**

1. **测试宏汇编器的指令生成:**  代码中包含了大量的 `__` 宏（例如 `__ movl`, `__ cmpl`, `__ ret` 等），这些宏实际上是调用 `MacroAssembler` 对象的成员函数来生成对应的 x64 汇编指令。测试涵盖了各种指令，例如：
    * 数据移动指令 (mov)
    * 比较指令 (cmp)
    * 跳转指令 (j)
    * 栈操作指令 (push, pop)
    * 算术运算指令 (xor)
    * Smi (Small Integer) 相关的操作指令 (SmiTag, SmiCompare, CheckSmi)
    * SIMD (Single Instruction, Multiple Data) 浮点操作指令 (Absph, Negph, Absps, Negps, Absd)
    * 内存寻址操作 (Operand)
    * 特殊的 V8 内部操作 (Abort, Check)

2. **生成和执行机器码:**  每个 `TEST_F` 函数都会创建一个 `MacroAssembler` 对象，使用 `__` 宏生成一段简单的机器码，然后将这段代码写入可执行的内存缓冲区。最后，它会通过函数指针的方式调用这段生成的机器码，并检查其执行结果是否符合预期。

3. **测试特定的 `MacroAssembler` 功能:**  每个测试用例 (`TEST_F`) 针对 `MacroAssembler` 的特定功能进行测试，例如：
    * `TestHardAbort`: 测试 `Abort` 指令，验证程序是否会按照预期终止。
    * `TestCheck`: 测试 `Check` 指令，验证条件检查是否正常工作。
    * `Smi` 系列测试 (`Smi`, `SmiMove`, `SmiCompare`, `SmiTag`, `SmiCheck`, `SmiIndex`): 测试 V8 中对小整数 (Smi) 的处理，包括移动、比较、标记和检查 Smi 类型。
    * `EmbeddedObj`: 测试 V8 如何嵌入对象到生成的代码中，并验证在垃圾回收时的处理。
    * `OperandOffset`: 测试各种内存寻址模式和偏移量的正确性。
    * `Float16x8Abs`, `Float16x8Neg`, `Float32x4Abs`, `Float32x4Neg`, `Float64x2Abs`: 测试 SIMD 浮点操作指令的绝对值和取反功能。

**关于文件扩展名和 Torque：**

`v8/test/unittests/assembler/macro-assembler-x64-unittest.cc` 的扩展名是 `.cc`，这表明它是一个 **C++ 源代码文件**。因此，它不是一个 V8 Torque 源代码文件。Torque 文件的扩展名通常是 `.tq`。

**与 JavaScript 的关系：**

`MacroAssembler` 是 V8 引擎中至关重要的组件，它负责将高级语言（例如 JavaScript 或 V8 的内部表示）编译成底层的机器码，以便 CPU 可以执行。

**JavaScript 示例说明 (以 Smi 相关功能为例):**

JavaScript 中的小整数在 V8 内部会尝试用 Smi (Small Integer) 来表示，以提高性能。 `MacroAssembler` 提供了处理 Smi 的指令。

```javascript
// JavaScript 代码
let a = 5;
let b = 10;
if (a < b) {
  console.log("a is less than b");
}
```

当 V8 执行这段 JavaScript 代码时，它可能会使用类似 `SmiCompare` 这样的宏汇编指令来比较 `a` 和 `b` 的值。  `SmiTag` 可能会被用来将字面量 `5` 和 `10` 转换成 Smi 的内部表示。

**代码逻辑推理示例 (针对 `TestCheck`):**

**假设输入:**  生成的汇编代码作为一个函数 `f` 被调用，接受一个整数参数。

**代码逻辑:**

```c++
  __ movl(rax, Immediate(17));  // 将立即数 17 移动到 rax 寄存器
  __ cmpl(rax, kCArgRegs[0]);  // 将 rax 的值与第一个参数寄存器 (kCArgRegs[0]) 的值进行比较
  __ Check(Condition::not_equal, AbortReason::kNoReason); // 如果 rax 的值不等于第一个参数，则继续执行；否则，触发 Abort
  __ ret(0); // 返回
```

**假设输入与输出:**

* **输入:** `f.Call(0)`
   * `kCArgRegs[0]` 的值为 0。
   * `rax` 的值为 17。
   * `rax` (17) 不等于 `kCArgRegs[0]` (0)，`Check` 条件成立。
   * **输出:** 函数正常返回。

* **输入:** `f.Call(17)`
   * `kCArgRegs[0]` 的值为 17。
   * `rax` 的值为 17。
   * `rax` (17) 等于 `kCArgRegs[0]` (17)，`Check` 条件不成立。
   * **输出:** 程序会调用 `Abort(AbortReason::kNoReason)`，导致程序终止 (由 `ASSERT_DEATH_IF_SUPPORTED` 断言捕捉)。

**涉及用户常见的编程错误 (间接相关):**

虽然这个单元测试主要测试 V8 内部的汇编器，但它所测试的功能与用户编程中可能出现的错误有关。例如：

* **整数溢出和类型处理不当:**  Smi 相关的测试确保 V8 内部正确处理小整数。如果 JavaScript 代码中涉及到超出 Smi 范围的整数，或者类型转换不当，可能会导致性能问题或意外的行为。V8 需要确保在这些情况下能够正确地处理。
* **内存访问错误:** `OperandOffset` 测试验证了内存寻址的正确性。在用户代码中，不正确的数组索引、指针操作等也可能导致类似的内存访问错误，例如访问越界。

**总结 (针对第 1 部分):**

这个 `v8/test/unittests/assembler/macro-assembler-x64-unittest.cc` 文件的第 1 部分主要 **测试了 V8 引擎中 x64 宏汇编器的基本指令生成和执行能力，特别是针对控制流、数据移动、比较操作以及 V8 特有的 Smi (小整数) 处理。** 它通过生成并执行简单的机器码片段，验证了 `MacroAssembler` 类的相关功能是否按预期工作，为 V8 引擎在 x64 架构上的代码生成提供了可靠的保障。

### 提示词
```
这是目录为v8/test/unittests/assembler/macro-assembler-x64-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/assembler/macro-assembler-x64-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
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

#include <stdlib.h>

#include <cstdint>
#include <cstring>
#include <limits>

#include "src/codegen/macro-assembler.h"
#include "src/codegen/x64/assembler-x64-inl.h"
#include "src/codegen/x64/assembler-x64.h"
#include "src/codegen/x64/register-x64.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/execution/simulator.h"
#include "src/heap/factory.h"
#include "src/numbers/conversions.h"
#include "src/objects/objects-inl.h"
#include "src/objects/smi.h"
#include "src/utils/ostreams.h"
#include "test/common/assembler-tester.h"
#include "test/common/value-helper.h"
#include "test/unittests/test-utils.h"
#include "third_party/fp16/src/include/fp16.h"

namespace v8 {
namespace internal {

#define __ masm.

// Test the x64 assembler by compiling some simple functions into
// a buffer and executing them.  These tests do not initialize the
// V8 library, create a context, or use any V8 objects.

using MacroAssemblerX64Test = TestWithIsolate;

void PrintCode(Isolate* isolate, CodeDesc desc) {
#ifdef OBJECT_PRINT
  DirectHandle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  StdoutStream os;
  Print(*code, os);
#endif  // OBJECT_PRINT
}

TEST_F(MacroAssemblerX64Test, TestHardAbort) {
  auto buffer = AllocateAssemblerBuffer();
  MacroAssembler masm(isolate(), AssemblerOptions{}, CodeObjectRequired::kNo,
                      buffer->CreateView());
  __ set_root_array_available(false);
  __ set_abort_hard(true);

  __ Abort(AbortReason::kNoReason);

  CodeDesc desc;
  masm.GetCode(isolate(), &desc);
  buffer->MakeExecutable();
  auto f = GeneratedCode<void>::FromBuffer(isolate(), buffer->start());

  ASSERT_DEATH_IF_SUPPORTED({ f.Call(); }, "abort: no reason");
}

TEST_F(MacroAssemblerX64Test, TestCheck) {
  auto buffer = AllocateAssemblerBuffer();
  MacroAssembler masm(isolate(), AssemblerOptions{}, CodeObjectRequired::kNo,
                      buffer->CreateView());
  __ set_root_array_available(false);
  __ set_abort_hard(true);

  // Fail if the first parameter is 17.
  __ movl(rax, Immediate(17));
  __ cmpl(rax, kCArgRegs[0]);
  __ Check(Condition::not_equal, AbortReason::kNoReason);
  __ ret(0);

  CodeDesc desc;
  masm.GetCode(isolate(), &desc);
  buffer->MakeExecutable();
  auto f = GeneratedCode<void, int>::FromBuffer(isolate(), buffer->start());

  f.Call(0);
  f.Call(18);
  ASSERT_DEATH_IF_SUPPORTED({ f.Call(17); }, "abort: no reason");
}

#undef __

namespace test_macro_assembler_x64 {

// Test the x64 assembler by compiling some simple functions into
// a buffer and executing them.  These tests do not initialize the
// V8 library, create a context, or use any V8 objects.
// The AMD64 calling convention is used, with the first five arguments
// in RSI, RDI, RDX, RCX, R8, and R9, and floating point arguments in
// the XMM registers.  The return value is in RAX.
// This calling convention is used on Linux, with GCC, and on Mac OS,
// with GCC.  A different convention is used on 64-bit windows.

using F0 = int();
using F1 = int(uint64_t*, uint64_t*, uint64_t*);
using F2 = int(uint64_t*, uint64_t*, uint64_t*, uint64_t*);
using F3 = int(int8_t, int8_t*, int8_t*, int8_t*);
using F4 = int(int16_t, int16_t*, int16_t*, int16_t*);
using F5 = int(int32_t, int32_t*, int32_t*, int32_t*);
using F6 = int(int64_t, int64_t*, int64_t*, int64_t*);
using F7 = int(double*, double*, double*);
using F8 = int(float*, float*, float*);
using F9 = int(int16_t*, int32_t*);
using F10 = int(int8_t*, int16_t*);
using F11 = int(uint16_t*, uint32_t*);
using F12 = int(uint8_t*, uint16_t*);
using F13 = int(float*, int32_t*);
using F14 = int(uint16_t*, int16_t*);
using F15 = int(uint16_t*, uint16_t*);
using F16 = int(double*, uint16_t*);

#define __ masm->

static void EntryCode(MacroAssembler* masm) {
  // Smi constant register is callee save.
  __ pushq(kRootRegister);
#ifdef V8_COMPRESS_POINTERS
  __ pushq(kPtrComprCageBaseRegister);
#endif
  __ InitializeRootRegister();
}

static void ExitCode(MacroAssembler* masm) {
#ifdef V8_COMPRESS_POINTERS
  __ popq(kPtrComprCageBaseRegister);
#endif
  __ popq(kRootRegister);
}

TEST_F(MacroAssemblerX64Test, Smi) {
  // clang-format off
  // Check that C++ Smi operations work as expected.
  int64_t test_numbers[] = {
      0, 1, -1, 127, 128, -128, -129, 255, 256, -256, -257,
      Smi::kMaxValue, static_cast<int64_t>(Smi::kMaxValue) + 1,
      Smi::kMinValue, static_cast<int64_t>(Smi::kMinValue) - 1
  };
  // clang-format on
  int test_number_count = 15;
  for (int i = 0; i < test_number_count; i++) {
    int64_t number = test_numbers[i];
    bool is_valid = Smi::IsValid(number);
    bool is_in_range = number >= Smi::kMinValue && number <= Smi::kMaxValue;
    CHECK_EQ(is_in_range, is_valid);
    if (is_valid) {
      Tagged<Smi> smi_from_intptr = Smi::FromIntptr(number);
      if (static_cast<int>(number) == number) {  // Is a 32-bit int.
        Tagged<Smi> smi_from_int = Smi::FromInt(static_cast<int32_t>(number));
        CHECK_EQ(smi_from_int, smi_from_intptr);
      }
      int64_t smi_value = smi_from_intptr.value();
      CHECK_EQ(number, smi_value);
    }
  }
}

static void TestMoveSmi(MacroAssembler* masm, Label* exit, int id,
                        Tagged<Smi> value) {
  __ movl(rax, Immediate(id));
  __ Move(rcx, value);
  __ Move(rdx, static_cast<intptr_t>(value.ptr()));
  __ cmp_tagged(rcx, rdx);
  __ j(not_equal, exit);
}

// Test that we can move a Smi value literally into a register.
TEST_F(MacroAssemblerX64Test, SmiMove) {
  Isolate* isolate = i_isolate();
  HandleScope handles(isolate);
  auto buffer = AllocateAssemblerBuffer();
  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes,
                           buffer->CreateView());
  MacroAssembler* masm = &assembler;  // Create a pointer for the __ macro.
  EntryCode(masm);
  Label exit;

  TestMoveSmi(masm, &exit, 1, Smi::zero());
  TestMoveSmi(masm, &exit, 2, Smi::FromInt(127));
  TestMoveSmi(masm, &exit, 3, Smi::FromInt(128));
  TestMoveSmi(masm, &exit, 4, Smi::FromInt(255));
  TestMoveSmi(masm, &exit, 5, Smi::FromInt(256));
  TestMoveSmi(masm, &exit, 6, Smi::FromInt(0xFFFF - 1));
  TestMoveSmi(masm, &exit, 7, Smi::FromInt(0xFFFF));
  TestMoveSmi(masm, &exit, 8, Smi::FromInt(0xFFFF + 1));
  TestMoveSmi(masm, &exit, 9, Smi::FromInt(Smi::kMaxValue));

  TestMoveSmi(masm, &exit, 10, Smi::FromInt(-1));
  TestMoveSmi(masm, &exit, 11, Smi::FromInt(-128));
  TestMoveSmi(masm, &exit, 12, Smi::FromInt(-129));
  TestMoveSmi(masm, &exit, 13, Smi::FromInt(-256));
  TestMoveSmi(masm, &exit, 14, Smi::FromInt(-257));
  TestMoveSmi(masm, &exit, 15, Smi::FromInt(-0xFFFF + 1));
  TestMoveSmi(masm, &exit, 16, Smi::FromInt(-0xFFFF));
  TestMoveSmi(masm, &exit, 17, Smi::FromInt(-0xFFFF - 1));
  TestMoveSmi(masm, &exit, 18, Smi::FromInt(Smi::kMinValue));

  __ xorq(rax, rax);  // Success.
  __ bind(&exit);
  ExitCode(masm);
  __ ret(0);

  CodeDesc desc;
  masm->GetCode(isolate, &desc);
  buffer->MakeExecutable();
  // Call the function from C++.
  auto f = GeneratedCode<F0>::FromBuffer(i_isolate(), buffer->start());
  int result = f.Call();
  CHECK_EQ(0, result);
}

void TestSmiCompare(MacroAssembler* masm, Label* exit, int id, int x, int y) {
  __ Move(rcx, Smi::FromInt(x));
  __ movq(r8, rcx);
  __ Move(rdx, Smi::FromInt(y));
  __ movq(r9, rdx);
  __ SmiCompare(rcx, rdx);
  if (x < y) {
    __ movl(rax, Immediate(id + 1));
    __ j(greater_equal, exit);
  } else if (x > y) {
    __ movl(rax, Immediate(id + 2));
    __ j(less_equal, exit);
  } else {
    CHECK_EQ(x, y);
    __ movl(rax, Immediate(id + 3));
    __ j(not_equal, exit);
  }
  // In this build config we clobber SMIs to stress test consumers, thus
  // SmiCompare can actually change unused bits.
#ifndef ENABLE_SLOW_DCHECKS
  __ movl(rax, Immediate(id + 4));
  __ cmpq(rcx, r8);
  __ j(not_equal, exit);
  __ incq(rax);
  __ cmpq(rdx, r9);
  __ j(not_equal, exit);
#endif

  if (x != y) {
    __ SmiCompare(rdx, rcx);
    if (y < x) {
      __ movl(rax, Immediate(id + 9));
      __ j(greater_equal, exit);
    } else {
      CHECK(y > x);
      __ movl(rax, Immediate(id + 10));
      __ j(less_equal, exit);
    }
  } else {
    __ cmpq(rcx, rcx);
    __ movl(rax, Immediate(id + 11));
    __ j(not_equal, exit);
#ifndef ENABLE_SLOW_DCHECKS
    __ incq(rax);
    __ cmpq(rcx, r8);
    __ j(not_equal, exit);
#endif
  }
}

// Test that we can compare smis for equality (and more).
TEST_F(MacroAssemblerX64Test, SmiCompare) {
  Isolate* isolate = i_isolate();
  HandleScope handles(isolate);
  auto buffer = AllocateAssemblerBuffer(2 * Assembler::kDefaultBufferSize);
  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes,
                           buffer->CreateView());

  MacroAssembler* masm = &assembler;
  EntryCode(masm);
  Label exit;

  TestSmiCompare(masm, &exit, 0x10, 0, 0);
  TestSmiCompare(masm, &exit, 0x20, 0, 1);
  TestSmiCompare(masm, &exit, 0x30, 1, 0);
  TestSmiCompare(masm, &exit, 0x40, 1, 1);
  TestSmiCompare(masm, &exit, 0x50, 0, -1);
  TestSmiCompare(masm, &exit, 0x60, -1, 0);
  TestSmiCompare(masm, &exit, 0x70, -1, -1);
  TestSmiCompare(masm, &exit, 0x80, 0, Smi::kMinValue);
  TestSmiCompare(masm, &exit, 0x90, Smi::kMinValue, 0);
  TestSmiCompare(masm, &exit, 0xA0, 0, Smi::kMaxValue);
  TestSmiCompare(masm, &exit, 0xB0, Smi::kMaxValue, 0);
  TestSmiCompare(masm, &exit, 0xC0, -1, Smi::kMinValue);
  TestSmiCompare(masm, &exit, 0xD0, Smi::kMinValue, -1);
  TestSmiCompare(masm, &exit, 0xE0, -1, Smi::kMaxValue);
  TestSmiCompare(masm, &exit, 0xF0, Smi::kMaxValue, -1);
  TestSmiCompare(masm, &exit, 0x100, Smi::kMinValue, Smi::kMinValue);
  TestSmiCompare(masm, &exit, 0x110, Smi::kMinValue, Smi::kMaxValue);
  TestSmiCompare(masm, &exit, 0x120, Smi::kMaxValue, Smi::kMinValue);
  TestSmiCompare(masm, &exit, 0x130, Smi::kMaxValue, Smi::kMaxValue);

  __ xorq(rax, rax);  // Success.
  __ bind(&exit);
  ExitCode(masm);
  __ ret(0);

  CodeDesc desc;
  masm->GetCode(isolate, &desc);
  buffer->MakeExecutable();
  // Call the function from C++.
  auto f = GeneratedCode<F0>::FromBuffer(i_isolate(), buffer->start());
  int result = f.Call();
  CHECK_EQ(0, result);
}

TEST_F(MacroAssemblerX64Test, SmiTag) {
  Isolate* isolate = i_isolate();
  HandleScope handles(isolate);
  auto buffer = AllocateAssemblerBuffer();
  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes,
                           buffer->CreateView());

  MacroAssembler* masm = &assembler;
  EntryCode(masm);
  Label exit;

  __ movq(rax, Immediate(1));  // Test number.
  __ movq(rcx, Immediate(0));
  __ SmiTag(rcx);
  __ Move(rdx, Smi::zero().ptr());
  __ cmp_tagged(rcx, rdx);
  __ j(not_equal, &exit);

  __ movq(rax, Immediate(2));  // Test number.
  __ movq(rcx, Immediate(1024));
  __ SmiTag(rcx);
  __ Move(rdx, Smi::FromInt(1024).ptr());
  __ cmp_tagged(rcx, rdx);
  __ j(not_equal, &exit);

  __ movq(rax, Immediate(3));  // Test number.
  __ movq(rcx, Immediate(-1));
  __ SmiTag(rcx);
  __ Move(rdx, Smi::FromInt(-1).ptr());
  __ cmp_tagged(rcx, rdx);
  __ j(not_equal, &exit);

  __ movq(rax, Immediate(4));  // Test number.
  __ movq(rcx, Immediate(Smi::kMaxValue));
  __ SmiTag(rcx);
  __ Move(rdx, Smi::FromInt(Smi::kMaxValue).ptr());
  __ cmp_tagged(rcx, rdx);
  __ j(not_equal, &exit);

  __ movq(rax, Immediate(5));  // Test number.
  __ movq(rcx, Immediate(Smi::kMinValue));
  __ SmiTag(rcx);
  __ Move(rdx, Smi::FromInt(Smi::kMinValue).ptr());
  __ cmp_tagged(rcx, rdx);
  __ j(not_equal, &exit);

  // Different target register.

  __ movq(rax, Immediate(6));  // Test number.
  __ movq(rcx, Immediate(0));
  __ SmiTag(r8, rcx);
  __ Move(rdx, Smi::zero().ptr());
  __ cmp_tagged(r8, rdx);
  __ j(not_equal, &exit);

  __ movq(rax, Immediate(7));  // Test number.
  __ movq(rcx, Immediate(1024));
  __ SmiTag(r8, rcx);
  __ Move(rdx, Smi::FromInt(1024).ptr());
  __ cmp_tagged(r8, rdx);
  __ j(not_equal, &exit);

  __ movq(rax, Immediate(8));  // Test number.
  __ movq(rcx, Immediate(-1));
  __ SmiTag(r8, rcx);
  __ Move(rdx, Smi::FromInt(-1).ptr());
  __ cmp_tagged(r8, rdx);
  __ j(not_equal, &exit);

  __ movq(rax, Immediate(9));  // Test number.
  __ movq(rcx, Immediate(Smi::kMaxValue));
  __ SmiTag(r8, rcx);
  __ Move(rdx, Smi::FromInt(Smi::kMaxValue).ptr());
  __ cmp_tagged(r8, rdx);
  __ j(not_equal, &exit);

  __ movq(rax, Immediate(10));  // Test number.
  __ movq(rcx, Immediate(Smi::kMinValue));
  __ SmiTag(r8, rcx);
  __ Move(rdx, Smi::FromInt(Smi::kMinValue).ptr());
  __ cmp_tagged(r8, rdx);
  __ j(not_equal, &exit);

  __ xorq(rax, rax);  // Success.
  __ bind(&exit);
  ExitCode(masm);
  __ ret(0);

  CodeDesc desc;
  masm->GetCode(isolate, &desc);
  buffer->MakeExecutable();
  // Call the function from C++.
  auto f = GeneratedCode<F0>::FromBuffer(i_isolate(), buffer->start());
  int result = f.Call();
  CHECK_EQ(0, result);
}

TEST_F(MacroAssemblerX64Test, SmiCheck) {
  Isolate* isolate = i_isolate();
  HandleScope handles(isolate);
  auto buffer = AllocateAssemblerBuffer();
  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes,
                           buffer->CreateView());

  MacroAssembler* masm = &assembler;
  EntryCode(masm);
  Label exit;
  Condition cond;

  __ movl(rax, Immediate(1));  // Test number.

  // CheckSmi

  __ movl(rcx, Immediate(0));
  __ SmiTag(rcx);
  cond = masm->CheckSmi(rcx);
  __ j(NegateCondition(cond), &exit);

  __ incq(rax);
  __ xorq(rcx, Immediate(kSmiTagMask));
  cond = masm->CheckSmi(rcx);
  __ j(cond, &exit);

  __ incq(rax);
  __ movl(rcx, Immediate(-1));
  __ SmiTag(rcx);
  cond = masm->CheckSmi(rcx);
  __ j(NegateCondition(cond), &exit);

  __ incq(rax);
  __ xorq(rcx, Immediate(kSmiTagMask));
  cond = masm->CheckSmi(rcx);
  __ j(cond, &exit);

  __ incq(rax);
  __ movl(rcx, Immediate(Smi::kMaxValue));
  __ SmiTag(rcx);
  cond = masm->CheckSmi(rcx);
  __ j(NegateCondition(cond), &exit);

  __ incq(rax);
  __ xorq(rcx, Immediate(kSmiTagMask));
  cond = masm->CheckSmi(rcx);
  __ j(cond, &exit);

  __ incq(rax);
  __ movl(rcx, Immediate(Smi::kMinValue));
  __ SmiTag(rcx);
  cond = masm->CheckSmi(rcx);
  __ j(NegateCondition(cond), &exit);

  __ incq(rax);
  __ xorq(rcx, Immediate(kSmiTagMask));
  cond = masm->CheckSmi(rcx);
  __ j(cond, &exit);

  // Success
  __ xorq(rax, rax);

  __ bind(&exit);
  ExitCode(masm);
  __ ret(0);

  CodeDesc desc;
  masm->GetCode(isolate, &desc);
  buffer->MakeExecutable();
  // Call the function from C++.
  auto f = GeneratedCode<F0>::FromBuffer(i_isolate(), buffer->start());
  int result = f.Call();
  CHECK_EQ(0, result);
}

void TestSmiIndex(MacroAssembler* masm, Label* exit, int id, int x) {
  __ movl(rax, Immediate(id));

  for (int i = 0; i < 8; i++) {
    __ Move(rcx, Smi::FromInt(x));
    SmiIndex index = masm->SmiToIndex(rdx, rcx, i);
    CHECK(index.reg == rcx || index.reg == rdx);
    __ shlq(index.reg, Immediate(index.scale));
    __ Move(r8, static_cast<intptr_t>(x) << i);
    __ cmpq(index.reg, r8);
    __ j(not_equal, exit);
    __ incq(rax);
    __ Move(rcx, Smi::FromInt(x));
    index = masm->SmiToIndex(rcx, rcx, i);
    CHECK(index.reg == rcx);
    __ shlq(rcx, Immediate(index.scale));
    __ Move(r8, static_cast<intptr_t>(x) << i);
    __ cmpq(rcx, r8);
    __ j(not_equal, exit);
    __ incq(rax);
  }
}

TEST_F(MacroAssemblerX64Test, EmbeddedObj) {
#ifdef V8_COMPRESS_POINTERS
  v8_flags.compact_on_every_full_gc = true;

  Isolate* isolate = i_isolate();
  HandleScope handles(isolate);
  auto buffer = AllocateAssemblerBuffer();
  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes,
                           buffer->CreateView());

  MacroAssembler* masm = &assembler;
  EntryCode(masm);
  Label exit;
  Handle<HeapObject> old_array = isolate->factory()->NewFixedArray(2000);
  Handle<HeapObject> my_array = isolate->factory()->NewFixedArray(1000);
  __ Move(rcx, my_array, RelocInfo::COMPRESSED_EMBEDDED_OBJECT);
  __ Move(rax, old_array, RelocInfo::FULL_EMBEDDED_OBJECT);
  __ bind(&exit);
  ExitCode(masm);
  __ ret(0);

  CodeDesc desc;
  masm->GetCode(isolate, &desc);
  DirectHandle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  StdoutStream os;
  Print(*code, os);
#endif
  using myF0 = Address();
  auto f = GeneratedCode<myF0>::FromAddress(isolate, code->instruction_start());
  Tagged<Object> result = Tagged<Object>(f.Call());
  CHECK_EQ(old_array->ptr(), result.ptr());

  // Collect garbage to ensure reloc info can be walked by the heap.
  InvokeMajorGC();
  InvokeMajorGC();
  InvokeMajorGC();

  PtrComprCageBase cage_base(isolate);

  // Test the user-facing reloc interface.
  const int mode_mask = RelocInfo::EmbeddedObjectModeMask();
  for (RelocIterator it(*code, mode_mask); !it.done(); it.next()) {
    RelocInfo::Mode mode = it.rinfo()->rmode();
    if (RelocInfo::IsCompressedEmbeddedObject(mode)) {
      CHECK_EQ(*my_array, it.rinfo()->target_object(cage_base));
    } else {
      CHECK(RelocInfo::IsFullEmbeddedObject(mode));
      CHECK_EQ(*old_array, it.rinfo()->target_object(cage_base));
    }
  }
#endif  // V8_COMPRESS_POINTERS
}

TEST_F(MacroAssemblerX64Test, SmiIndex) {
  Isolate* isolate = i_isolate();
  HandleScope handles(isolate);
  auto buffer = AllocateAssemblerBuffer(2 * Assembler::kDefaultBufferSize);
  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes,
                           buffer->CreateView());

  MacroAssembler* masm = &assembler;
  EntryCode(masm);
  Label exit;

  TestSmiIndex(masm, &exit, 0x10, 0);
  TestSmiIndex(masm, &exit, 0x20, 1);
  TestSmiIndex(masm, &exit, 0x30, 100);
  TestSmiIndex(masm, &exit, 0x40, 1000);
  TestSmiIndex(masm, &exit, 0x50, Smi::kMaxValue);

  __ xorq(rax, rax);  // Success.
  __ bind(&exit);
  ExitCode(masm);
  __ ret(0);

  CodeDesc desc;
  masm->GetCode(isolate, &desc);
  buffer->MakeExecutable();
  // Call the function from C++.
  auto f = GeneratedCode<F0>::FromBuffer(i_isolate(), buffer->start());
  int result = f.Call();
  CHECK_EQ(0, result);
}

TEST_F(MacroAssemblerX64Test, OperandOffset) {
  uint32_t data[256];
  for (uint32_t i = 0; i < 256; i++) {
    data[i] = i * 0x01010101;
  }

  Isolate* isolate = i_isolate();
  HandleScope handles(isolate);
  auto buffer = AllocateAssemblerBuffer();
  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes,
                           buffer->CreateView());

  MacroAssembler* masm = &assembler;
  Label exit;

  EntryCode(masm);
  __ pushq(r13);
  __ pushq(r14);
  __ pushq(rbx);
  __ pushq(rbp);
  __ pushq(Immediate(0x100));  // <-- rbp
  __ movq(rbp, rsp);
  __ pushq(Immediate(0x101));
  __ pushq(Immediate(0x102));
  __ pushq(Immediate(0x103));
  __ pushq(Immediate(0x104));
  __ pushq(Immediate(0x105));  // <-- rbx
  __ pushq(Immediate(0x106));
  __ pushq(Immediate(0x107));
  __ pushq(Immediate(0x108));
  __ pushq(Immediate(0x109));  // <-- rsp
  // rbp = rsp[9]
  // r15 = rsp[3]
  // rbx = rsp[5]
  // r13 = rsp[7]
  __ leaq(r14, Operand(rsp, 3 * kSystemPointerSize));
  __ leaq(r13, Operand(rbp, -3 * kSystemPointerSize));
  __ leaq(rbx, Operand(rbp, -5 * kSystemPointerSize));
  __ movl(rcx, Immediate(2));
  __ Move(r8, reinterpret_cast<Address>(&data[128]), RelocInfo::NO_INFO);
  __ movl(rax, Immediate(1));

  Operand sp0 = Operand(rsp, 0);

  // Test 1.
  __ movl(rdx, sp0);  // Sanity check.
  __ cmpl(rdx, Immediate(0x109));
  __ j(not_equal, &exit);
  __ incq(rax);

  // Test 2.
  // Zero to non-zero displacement.
  __ movl(rdx, Operand(sp0, 2 * kSystemPointerSize));
  __ cmpl(rdx, Immediate(0x107));
  __ j(not_equal, &exit);
  __ incq(rax);

  Operand sp2 = Operand(rsp, 2 * kSystemPointerSize);

  // Test 3.
  __ movl(rdx, sp2);  // Sanity check.
  __ cmpl(rdx, Immediate(0x107));
  __ j(not_equal, &exit);
  __ incq(rax);

  __ movl(rdx, Operand(sp2, 2 * kSystemPointerSize));
  __ cmpl(rdx, Immediate(0x105));
  __ j(not_equal, &exit);
  __ incq(rax);

  // Non-zero to zero displacement.
  __ movl(rdx, Operand(sp2, -2 * kSystemPointerSize));
  __ cmpl(rdx, Immediate(0x109));
  __ j(not_equal, &exit);
  __ incq(rax);

  Operand sp2c2 =
      Operand(rsp, rcx, times_system_pointer_size, 2 * kSystemPointerSize);

  // Test 6.
  __ movl(rdx, sp2c2);  // Sanity check.
  __ cmpl(rdx, Immediate(0x105));
  __ j(not_equal, &exit);
  __ incq(rax);

  __ movl(rdx, Operand(sp2c2, 2 * kSystemPointerSize));
  __ cmpl(rdx, Immediate(0x103));
  __ j(not_equal, &exit);
  __ incq(rax);

  // Non-zero to zero displacement.
  __ movl(rdx, Operand(sp2c2, -2 * kSystemPointerSize));
  __ cmpl(rdx, Immediate(0x107));
  __ j(not_equal, &exit);
  __ incq(rax);

  Operand bp0 = Operand(rbp, 0);

  // Test 9.
  __ movl(rdx, bp0);  // Sanity check.
  __ cmpl(rdx, Immediate(0x100));
  __ j(not_equal, &exit);
  __ incq(rax);

  // Zero to non-zero displacement.
  __ movl(rdx, Operand(bp0, -2 * kSystemPointerSize));
  __ cmpl(rdx, Immediate(0x102));
  __ j(not_equal, &exit);
  __ incq(rax);

  Operand bp2 = Operand(rbp, -2 * kSystemPointerSize);

  // Test 11.
  __ movl(rdx, bp2);  // Sanity check.
  __ cmpl(rdx, Immediate(0x102));
  __ j(not_equal, &exit);
  __ incq(rax);

  // Non-zero to zero displacement.
  __ movl(rdx, Operand(bp2, 2 * kSystemPointerSize));
  __ cmpl(rdx, Immediate(0x100));
  __ j(not_equal, &exit);
  __ incq(rax);

  __ movl(rdx, Operand(bp2, -2 * kSystemPointerSize));
  __ cmpl(rdx, Immediate(0x104));
  __ j(not_equal, &exit);
  __ incq(rax);

  Operand bp2c4 =
      Operand(rbp, rcx, times_system_pointer_size, -4 * kSystemPointerSize);

  // Test 14:
  __ movl(rdx, bp2c4);  // Sanity check.
  __ cmpl(rdx, Immediate(0x102));
  __ j(not_equal, &exit);
  __ incq(rax);

  __ movl(rdx, Operand(bp2c4, 2 * kSystemPointerSize));
  __ cmpl(rdx, Immediate(0x100));
  __ j(not_equal, &exit);
  __ incq(rax);

  __ movl(rdx, Operand(bp2c4, -2 * kSystemPointerSize));
  __ cmpl(rdx, Immediate(0x104));
  __ j(not_equal, &exit);
  __ incq(rax);

  Operand bx0 = Operand(rbx, 0);

  // Test 17.
  __ movl(rdx, bx0);  // Sanity check.
  __ cmpl(rdx, Immediate(0x105));
  __ j(not_equal, &exit);
  __ incq(rax);

  __ movl(rdx, Operand(bx0, 5 * kSystemPointerSize));
  __ cmpl(rdx, Immediate(0x100));
  __ j(not_equal, &exit);
  __ incq(rax);

  __ movl(rdx, Operand(bx0, -4 * kSystemPointerSize));
  __ cmpl(rdx, Immediate(0x109));
  __ j(not_equal, &exit);
  __ incq(rax);

  Operand bx2 = Operand(rbx, 2 * kSystemPointerSize);

  // Test 20.
  __ movl(rdx, bx2);  // Sanity check.
  __ cmpl(rdx, Immediate(0x103));
  __ j(not_equal, &exit);
  __ incq(rax);

  __ movl(rdx, Operand(bx2, 2 * kSystemPointerSize));
  __ cmpl(rdx, Immediate(0x101));
  __ j(not_equal, &exit);
  __ incq(rax);

  // Non-zero to zero displacement.
  __ movl(rdx, Operand(bx2, -2 * kSystemPointerSize));
  __ cmpl(rdx, Immediate(0x105));
  __ j(not_equal, &exit);
  __ incq(rax);

  Operand bx2c2 =
      Operand(rbx, rcx, times_system_pointer_size, -2 * kSystemPointerSize);

  // Test 23.
  __ movl(rdx, bx2c2);  // Sanity check.
  __ cmpl(rdx, Immediate(0x105));
  __ j(not_equal, &exit);
  __ incq(rax);

  __ movl(rdx, Operand(bx2c2, 2 * kSystemPointerSize));
  __ cmpl(rdx, Immediate(0x103));
  __ j(not_equal, &exit);
  __ incq(rax);

  __ movl(rdx, Operand(bx2c2, -2 * kSystemPointerSize));
  __ cmpl(rdx, Immediate(0x107));
  __ j(not_equal, &exit);
  __ incq(rax);

  Operand r80 = Operand(r8, 0);

  // Test 26.
  __ movl(rdx, r80);  // Sanity check.
  __ cmpl(rdx, Immediate(0x80808080));
  __ j(not_equal, &exit);
  __ incq(rax);

  __ movl(rdx, Operand(r80, -8 * kIntSize));
  __ cmpl(rdx, Immediate(0x78787878));
  __ j(not_equal, &exit);
  __ incq(rax);

  __ movl(rdx, Operand(r80, 8 * kIntSize));
  __ cmpl(rdx, Immediate(0x88888888));
  __ j(not_equal, &exit);
  __ incq(rax);

  __ movl(rdx, Operand(r80, -64 * kIntSize));
  __ cmpl(rdx, Immediate(0x40404040));
  __ j(not_equal, &exit);
  __ incq(rax);

  __ movl(rdx, Operand(r80, 64 * kIntSize));
  __ cmpl(rdx, Immediate(0xC0C0C0C0));
  __ j(not_equal, &exit);
  __ incq(rax);

  Operand r88 = Operand(r8, 8 * kIntSize);

  // Test 31.
  __ movl(rdx, r88);  // Sanity check.
  __ cmpl(rdx, Immediate(0x88888888));
  __ j(not_equal, &exit);
  __ incq(rax);

  __ movl(rdx, Operand(r88, -8 * kIntSize));
  __ cmpl(rdx, Immediate(0x80808080));
  __ j(not_equal, &exit);
  __ incq(rax);

  __ movl(rdx, Operand(r88, 8 * kIntSize));
  __ cmpl(rdx, Immediate(0x90909090));
  __ j(not_equal, &exit);
  __ incq(rax);

  __ movl(rdx, Operand(r88, -64 * kIntSize));
  __ cmpl(rdx, Immediate(0x48484848));
  __ j(not_equal, &exit);
  __ incq(rax);

  __ movl(rdx, Operand(r88, 64 * kIntSize));
  __ cmpl(rdx, Immediate(0xC8C8C8C8));
  __ j(not_equal, &exit);
  __ incq(rax);

  Operand r864 = Operand(r8, 64 * kIntSize);

  // Test 36.
  __ movl(rdx, r864);  // Sanity check.
  __ cmpl(rdx, Immediate(0xC0C0C0C0));
  __ j(not_equal, &exit);
  __ incq(rax);

  __ movl(rdx, Operand(r864, -8 * kIntSize));
  __ cmpl(rdx, Immediate(0xB8B8B8B8));
  __ j(not_equal, &exit);
  __ incq(rax);

  __ movl(rdx, Operand(r864, 8 * kIntSize));
  __ cmpl(rdx, Immediate(0xC8C8C8C8));
  __ j(not_equal, &exit);
  __ incq(rax);

  __ movl(rdx, Operand(r864, -64 * kIntSize));
  __ cmpl(rdx, Immediate(0x80808080));
  __ j(not_equal, &exit);
  __ incq(rax);

  __ movl(rdx, Operand(r864, 32 * kIntSize));
  __ cmpl(rdx, Immediate(0xE0E0E0E0));
  __ j(not_equal, &exit);
  __ incq(rax);

  // 32-bit offset to 8-bit offset.
  __ movl(rdx, Operand(r864, -60 * kIntSize));
  __ cmpl(rdx, Immediate(0x84848484));
  __ j(not_equal, &exit);
  __ incq(rax);

  __ movl(rdx, Operand(r864, 60 * kIntSize));
  __ cmpl(rdx, Immediate(0xFCFCFCFC));
  __ j(not_equal, &exit);
  __ incq(rax);

  // Test unaligned offsets.

  // Test 43.
  __ movl(rdx, Operand(r80, 2));
  __ cmpl(rdx, Immediate(0x81818080));
  __ j(not_equal, &exit);
  __ incq(rax);

  __ movl(rdx, Operand(r80, -2));
  __ cmpl(rdx, Immediate(0x80807F7F));
  __ j(not_equal, &exit);
  __ incq(rax);

  __ movl(rdx, Operand(r80, 126));
  __ cmpl(rdx, Immediate(0xA0A09F9F));
  __ j(not_equal, &exit);
  __ incq(rax);

  __ movl(rdx, Operand(r80, -126));
  __ cmpl(rdx, Immediate(0x61616060));
  __ j(not_equal, &exit);
  __ incq(rax);

  __ movl(rdx, Operand(r80, 254));
  __ cmpl(rdx, Immediate(0xC0C0BFBF));
  __ j(not_equal, &exit);
  __ incq(rax);

  __ movl(rdx, Operand(r80, -254));
  __ cmpl(rdx, Immediate(0x41414040));
  __ j(not_equal, &exit);
  __ incq(rax);

  // Success.

  __ movl(rax, Immediate(0));
  __ bind(&exit);
  __ leaq(rsp, Operand(rbp, kSystemPointerSize));
  __ popq(rbp);
  __ popq(rbx);
  __ popq(r14);
  __ popq(r13);
  ExitCode(masm);
  __ ret(0);

  CodeDesc desc;
  masm->GetCode(isolate, &desc);
  buffer->MakeExecutable();
  // Call the function from C++.
  auto f = GeneratedCode<F0>::FromBuffer(i_isolate(), buffer->start());
  int result = f.Call();
  CHECK_EQ(0, result);
}

#define STORE(val, offset)                                              \
  __ movq(kScratchRegister, Immediate(fp16_ieee_from_fp32_value(val))); \
  __ movw(Operand(rsp, offset * kFloat16Size), kScratchRegister);

#define LOAD_AND_CHECK(val, offset, op)                                     \
  __ incq(rax);                                                             \
  __ movq(kScratchRegister, Immediate(fp16_ieee_from_fp32_value(op(val)))); \
  __ cmpw(kScratchRegister, Operand(rsp, offset * kFloat16Size));           \
  __ j(not_equal, exit);

void TestFloat16x8Abs(MacroAssembler* masm, Label* exit, float x, float y,
                      float z, float w, float a, float b, float c, float d) {
  __ AllocateStackSpace(kSimd128Size);

  STORE(x, 0)
  STORE(y, 1)
  STORE(z, 2)
  STORE(w, 3)
  STORE(a, 4)
  STORE(b, 5)
  STORE(c, 6)
  STORE(d, 7)

  __ Movups(xmm0, Operand(rsp, 0));
  __ Absph(xmm0, xmm0, kScratchRegister);
  __ Movups(Operand(rsp, 0), xmm0);

  LOAD_AND_CHECK(x, 0, fabsf)
  LOAD_AND_CHECK(y, 1, fabsf)
  LOAD_AND_CHECK(z, 2, fabsf)
  LOAD_AND_CHECK(w, 3, fabsf)
  LOAD_AND_CHECK(a, 4, fabsf)
  LOAD_AND_CHECK(b, 5, fabsf)
  LOAD_AND_CHECK(c, 6, fabsf)
  LOAD_AND_CHECK(d, 7, fabsf)

  __ addq(rsp, Immediate(kSimd128Size));
}

void TestFloat16x8Neg(MacroAssembler* masm, Label* exit, float x, float y,
                      float z, float w, float a, float b, float c, float d) {
  __ AllocateStackSpace(kSimd128Size);

  STORE(x, 0)
  STORE(y, 1)
  STORE(z, 2)
  STORE(w, 3)
  STORE(a, 4)
  STORE(b, 5)
  STORE(c, 6)
  STORE(d, 7)

  __ Movups(xmm0, Operand(rsp, 0));
  __ Negph(xmm0, xmm0, kScratchRegister);
  __ Movups(Operand(rsp, 0), xmm0);

  LOAD_AND_CHECK(x, 0, -)
  LOAD_AND_CHECK(y, 1, -)
  LOAD_AND_CHECK(z, 2, -)
  LOAD_AND_CHECK(w, 3, -)
  LOAD_AND_CHECK(a, 4, -)
  LOAD_AND_CHECK(b, 5, -)
  LOAD_AND_CHECK(c, 6, -)
  LOAD_AND_CHECK(d, 7, -)

  __ addq(rsp, Immediate(kSimd128Size));
}

#undef STORE
#undef LOAD_AND_CHECK

void TestFloat32x4Abs(MacroAssembler* masm, Label* exit, float x, float y,
                      float z, float w) {
  __ AllocateStackSpace(kSimd128Size);

  __ Move(xmm1, x);
  __ Movss(Operand(rsp, 0 * kFloatSize), xmm1);
  __ Move(xmm2, y);
  __ Movss(Operand(rsp, 1 * kFloatSize), xmm2);
  __ Move(xmm3, z);
  __ Movss(Operand(rsp, 2 * kFloatSize), xmm3);
  __ Move(xmm4, w);
  __ Movss(Operand(rsp, 3 * kFloatSize), xmm4);
  __ Movups(xmm0, Operand(rsp, 0));

  __ Absps(xmm0, xmm0, kScratchRegister);
  __ Movups(Operand(rsp, 0), xmm0);

  __ incq(rax);
  __ Move(xmm1, fabsf(x));
  __ Ucomiss(xmm1, Operand(rsp, 0 * kFloatSize));
  __ j(not_equal, exit);
  __ incq(rax);
  __ Move(xmm2, fabsf(y));
  __ Ucomiss(xmm2, Operand(rsp, 1 * kFloatSize));
  __ j(not_equal, exit);
  __ incq(rax);
  __ Move(xmm3, fabsf(z));
  __ Ucomiss(xmm3, Operand(rsp, 2 * kFloatSize));
  __ j(not_equal, exit);
  __ incq(rax);
  __ Move(xmm4, fabsf(w));
  __ Ucomiss(xmm4, Operand(rsp, 3 * kFloatSize));
  __ j(not_equal, exit);

  __ addq(rsp, Immediate(kSimd128Size));
}

void TestFloat32x4Neg(MacroAssembler* masm, Label* exit, float x, float y,
                      float z, float w) {
  __ AllocateStackSpace(kSimd128Size);

  __ Move(xmm1, x);
  __ Movss(Operand(rsp, 0 * kFloatSize), xmm1);
  __ Move(xmm2, y);
  __ Movss(Operand(rsp, 1 * kFloatSize), xmm2);
  __ Move(xmm3, z);
  __ Movss(Operand(rsp, 2 * kFloatSize), xmm3);
  __ Move(xmm4, w);
  __ Movss(Operand(rsp, 3 * kFloatSize), xmm4);
  __ Movups(xmm0, Operand(rsp, 0));

  __ Negps(xmm0, xmm0, kScratchRegister);
  __ Movups(Operand(rsp, 0), xmm0);

  __ incq(rax);
  __ Move(xmm1, -x);
  __ Ucomiss(xmm1, Operand(rsp, 0 * kFloatSize));
  __ j(not_equal, exit);
  __ incq(rax);
  __ Move(xmm2, -y);
  __ Ucomiss(xmm2, Operand(rsp, 1 * kFloatSize));
  __ j(not_equal, exit);
  __ incq(rax);
  __ Move(xmm3, -z);
  __ Ucomiss(xmm3, Operand(rsp, 2 * kFloatSize));
  __ j(not_equal, exit);
  __ incq(rax);
  __ Move(xmm4, -w);
  __ Ucomiss(xmm4, Operand(rsp, 3 * kFloatSize));
  __ j(not_equal, exit);

  __ addq(rsp, Immediate(kSimd128Size));
}

void TestFloat64x2Abs(MacroAssembler* masm, Label* exit, double x, double y) {
  __ AllocateStackSpace(kSimd128Size);

  __ Move(xmm1, x);
  __ Movsd(Operand(rsp, 0 * kDoubleSize), xmm1);
```