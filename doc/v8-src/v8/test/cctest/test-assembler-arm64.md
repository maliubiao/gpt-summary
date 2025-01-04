Response: My thought process for summarizing the C++ code and relating it to JavaScript:

1. **Understand the Goal:** The request asks for a summary of the C++ code's functionality and to illustrate its connection to JavaScript with examples. The "part 1 of 8" indicates a larger testing framework.

2. **Identify Key Components:** I scanned the code for recognizable patterns and keywords. I noticed:
    * Copyright and license information (standard boilerplate, less important for functionality).
    * Includes: `stdio.h`, `stdlib.h`, `string.h`, `cmath`, `limits`, `optional`, and V8-specific headers like `assembler-arm64-inl.h`, `decoder-arm64-inl.h`, `macro-assembler-arm64-inl.h`, `simulator-arm64.h`, `factory.h`. These strongly suggest this code is part of the V8 JavaScript engine, specifically for testing its ARM64 assembler.
    * Namespaces: `v8::internal`. This further confirms the V8 context.
    * Macros: `TEST`, `SETUP`, `START`, `END`, `RUN`, `CHECK_EQUAL_*`. These look like a custom testing framework.
    * Simulator-related definitions (`USE_SIMULATOR`, `CAN_RUN`). This confirms testing in a simulated environment is supported.
    * Register names: `x0`, `x1`, `w0`, `sp`, `lr`. These are ARM64 registers.

3. **Infer High-Level Functionality:** Based on the includes and macros, the primary purpose is clearly **testing the ARM64 assembler within the V8 engine**. The `TEST` macros define individual test cases, and the other macros manage setup, execution, and verification.

4. **Analyze the Test Structure:** The `SETUP()`, `START()`, `END()`, and `RUN()` macros define the typical structure of a test. Each test seems to:
    * `SETUP()`: Initializes the testing environment.
    * `START()`:  Prepares the assembler buffer.
    * Assembler instructions (`__ mov`, `__ add`, `__ mvn`, etc.): This is the core of the tests, exercising different ARM64 instructions.
    * `END()`:  Finalizes the assembly process and prepares for execution.
    * `RUN()`: Executes the generated ARM64 code (either in a simulator or on real hardware).
    * `CHECK_EQUAL_*`:  Verifies the results by comparing register values and flags against expected values.

5. **Identify Specific Test Categories:**  I skimmed through the test names (`stack_ops`, `mvn`, `mov`, `orr`, `and_`, `div`, `branch_cond`, etc.). These names indicate tests for various ARM64 instruction groups (stack operations, logical operations, move instructions, arithmetic operations, branching, etc.).

6. **Connect to JavaScript:** This is the crucial part. I need to explain *why* testing the ARM64 assembler is relevant to JavaScript.
    * **V8's Role:**  V8 compiles JavaScript code into machine code for execution. On ARM64 architectures, it uses an ARM64 assembler to generate this machine code.
    * **Assembler's Importance:** The correctness and efficiency of the assembler are critical for JavaScript performance. Bugs in the assembler can lead to incorrect execution or crashes.
    * **Test's Purpose:** These tests ensure that the assembler generates the correct ARM64 instructions for various JavaScript operations.

7. **Develop JavaScript Examples:** To illustrate the connection, I need to provide simple JavaScript code snippets and explain how they *might* be translated into ARM64 instructions (the exact translation is complex and performed by V8, but I can provide conceptual examples). I focused on operations that have clear parallels in assembly:
    * **Variable assignment:** `let x = 1;` can be linked to `mov` instructions.
    * **Arithmetic operations:** `x + y` can be linked to `add` instructions.
    * **Logical operations:** `x & y`, `x | y` can be linked to `and`, `orr` instructions.
    * **Control flow:** `if (condition) { ... }` can be linked to branch instructions.

8. **Structure the Summary:** I organized the summary into clear sections:
    * **Purpose:** A concise statement of the file's main goal.
    * **Functionality Breakdown:**  A more detailed explanation of the testing framework and what it tests.
    * **Relationship to JavaScript:** The crucial link explaining the significance of the tests.
    * **JavaScript Examples:** Concrete examples demonstrating the connection.

9. **Refine and Iterate:** I reviewed the summary for clarity, accuracy, and completeness. I made sure the JavaScript examples were simple and effectively illustrated the relationship. I also emphasized the low-level nature of the C++ code compared to the high-level abstraction of JavaScript. The "part 1 of 8" also reminded me to mention that this is likely part of a larger testing effort.
这是一个C++源代码文件，属于V8 JavaScript引擎的测试套件。 它的主要功能是 **测试V8引擎中用于ARM64架构的汇编器 (Assembler-arm64)** 的正确性。

更具体地说，这部分代码（第1部分）定义了一个测试框架和一些基础的汇编指令测试用例。

**功能归纳：**

1. **测试框架构建:**  定义了一套用于编写和执行汇编器测试的宏和工具，例如 `TEST`, `SETUP`, `START`, `END`, `RUN`, `CHECK_EQUAL_*` 等。这些宏简化了测试用例的编写，允许开发者专注于要测试的汇编指令。
2. **基础汇编指令测试:**  包含了针对ARM64架构的一些基本汇编指令的单元测试，例如：
    * **栈操作:** `stack_ops` 测试了与栈指针 (`sp`) 相关的操作。
    * **位运算指令:** `mvn`, `orr`, `orn`, `and_`, `ands`, `bic`, `bics`, `eor`, `eon` 测试了各种位运算指令。
    * **数据移动指令:** `mov`, `move_pair` 测试了数据在寄存器之间的移动，包括立即数和寄存器操作数。
    * **算术运算指令:** `mul`, `smull`, `madd`, `msub`, `smulh`, `smaddl_umaddl`, `smsubl_umsubl`, `div` 测试了乘法、加法、减法和除法指令。
    * **位操作指令:** `rbit_rev`, `clz_cls` 测试了位反转、位逆序、前导零计数和前导符号位计数指令。
    * **分支指令:** `label`, `branch_at_start`, `adr`, `adr_far`, `branch_cond`, `branch_to_reg`, `bti`, `unguarded_bti_is_nop`, `compare_branch`, `test_branch`, `far_branch_backward`, `far_branch_simple_veneer`, `far_branch_veneer_link_chain`, `far_branch_veneer_broken_link_chain`, `branch_type` 测试了各种类型的分支指令，包括条件分支、无条件分支、跳转到寄存器等。
3. **模拟器支持:** 代码中包含了对模拟器 (`USE_SIMULATOR`) 的支持，允许在没有实际ARM64硬件的情况下运行测试。
4. **寄存器和标志检查:** 提供了 `CHECK_EQUAL_*` 宏来断言执行汇编代码后，寄存器和处理器标志的值是否符合预期。

**与JavaScript的功能关系及JavaScript示例：**

这个C++文件直接测试的是V8引擎的底层汇编器，而汇编器负责将JavaScript代码编译成机器码在ARM64架构上执行。 因此，这个文件的功能与JavaScript的性能和正确性 **息息相关**。

当V8引擎执行JavaScript代码时，它会根据代码的逻辑和目标架构（这里是ARM64）生成相应的汇编指令。 这个测试文件中的每一个测试用例都在验证特定汇编指令的行为是否正确。 如果这些底层指令的行为不正确，那么最终执行的JavaScript代码也可能会出错。

**JavaScript 示例：**

以下是一些简单的JavaScript代码片段，以及它们可能在V8引擎内部被转换成的ARM64汇编指令的 *概念性* 对应（实际转换过程会更复杂，涉及优化等）：

**1. 变量赋值和数据移动:**

```javascript
let x = 10;
let y = x;
```

在V8内部，这可能会涉及到 `mov` 指令：

```assembly
// 假设将 JavaScript 变量 x 映射到 ARM64 寄存器 x0
mov x0, #10  // 将立即数 10 移动到寄存器 x0

// 假设将 JavaScript 变量 y 映射到 ARM64 寄存器 x1
mov x1, x0   // 将寄存器 x0 的值移动到寄存器 x1
```

测试文件中的 `TEST(mov)` 用例正是为了验证 `mov` 指令的行为是否符合预期。

**2. 算术运算:**

```javascript
let sum = a + b;
```

这可能会涉及到 `add` 指令：

```assembly
// 假设将 JavaScript 变量 a 映射到 ARM64 寄存器 w0
// 假设将 JavaScript 变量 b 映射到 ARM64 寄存器 w1
add w2, w0, w1  // 将寄存器 w0 和 w1 的值相加，结果存储到寄存器 w2
```

测试文件中的 `TEST(orr)` （虽然名字是 OR，但也测试了操作数的不同形式）等用例，覆盖了各种算术和逻辑运算指令，确保 V8 生成的这些指令能够正确执行。

**3. 条件判断:**

```javascript
if (x > 5) {
  // ...
}
```

这可能会涉及到比较指令 (`cmp`) 和条件分支指令 (`b.gt`):

```assembly
// 假设将 JavaScript 变量 x 映射到 ARM64 寄存器 x0
cmp x0, #5    // 将寄存器 x0 的值与立即数 5 进行比较
b.le  else_block // 如果 x0 小于等于 5，则跳转到 else_block

// ... if 块中的代码 ...

b end_if

else_block:
// ... else 块中的代码 ...

end_if:
```

测试文件中的 `TEST(branch_cond)` 用例测试了各种条件分支指令在不同条件下的行为，确保 V8 在处理 JavaScript 的 `if` 语句等控制流时能够生成正确的汇编代码。

**总结:**

`v8/test/cctest/test-assembler-arm64.cc` 的第1部分是V8引擎中ARM64汇编器测试的基础部分，它通过定义测试框架和提供针对基本汇编指令的单元测试，来保障V8引擎在ARM64架构上生成正确且高效的机器码，从而直接影响JavaScript代码的执行性能和正确性。 开发者编写的每一个JavaScript功能，最终都依赖于这些底层的汇编指令的正确执行。

Prompt: 
```
这是目录为v8/test/cctest/test-assembler-arm64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共8部分，请归纳一下它的功能

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cmath>
#include <limits>
#include <optional>

#include "src/base/utils/random-number-generator.h"
#include "src/codegen/arm64/assembler-arm64-inl.h"
#include "src/codegen/arm64/decoder-arm64-inl.h"
#include "src/codegen/arm64/macro-assembler-arm64-inl.h"
#include "src/codegen/arm64/utils-arm64.h"
#include "src/codegen/macro-assembler.h"
#include "src/diagnostics/arm64/disasm-arm64.h"
#include "src/execution/arm64/simulator-arm64.h"
#include "src/heap/factory.h"
#include "test/cctest/cctest.h"
#include "test/cctest/test-utils-arm64.h"
#include "test/common/assembler-tester.h"
#include "third_party/fp16/src/include/fp16.h"

namespace v8 {
namespace internal {

// Test infrastructure.
//
// Tests are functions which accept no parameters and have no return values.
// The testing code should not perform an explicit return once completed. For
// example to test the mov immediate instruction a very simple test would be:
//
//   TEST(mov_x0_one) {
//     SETUP();
//
//     START();
//     __ mov(x0, Operand(1));
//     END();
//
//     RUN();
//
//     CHECK_EQUAL_64(1, x0);
//   }
//
// Within a START ... END block all registers but sp can be modified. sp has to
// be explicitly saved/restored. The END() macro replaces the function return
// so it may appear multiple times in a test if the test has multiple exit
// points.
//
// Once the test has been run all integer and floating point registers as well
// as flags are accessible through a RegisterDump instance, see
// utils-arm64.cc for more info on RegisterDump.
//
// We provide some helper assert to handle common cases:
//
//   CHECK_EQUAL_32(int32_t, int_32t)
//   CHECK_EQUAL_FP32(float, float)
//   CHECK_EQUAL_32(int32_t, W register)
//   CHECK_EQUAL_FP32(float, S register)
//   CHECK_EQUAL_64(int64_t, int_64t)
//   CHECK_EQUAL_FP64(double, double)
//   CHECK_EQUAL_64(int64_t, X register)
//   CHECK_EQUAL_64(X register, X register)
//   CHECK_EQUAL_FP64(double, D register)
//
// e.g. CHECK_EQUAL_64(0.5, d30);
//
// If more advance computation is required before the assert then access the
// RegisterDump named core directly:
//
//   CHECK_EQUAL_64(0x1234, core.xreg(0) & 0xFFFF);

#if 0  // TODO(all): enable.
static v8::Persistent<v8::Context> env;

static void InitializeVM() {
  if (env.IsEmpty()) {
    env = v8::Context::New();
  }
}
#endif

#define __ masm.

#define BUF_SIZE 8192
#define SETUP() SETUP_SIZE(BUF_SIZE)

#define INIT_V8() CcTest::InitializeVM();

// Declare that a test will use an optional feature, which means execution needs
// to be behind CAN_RUN().
#define SETUP_FEATURE(feature)                            \
  const bool can_run = CpuFeatures::IsSupported(feature); \
  USE(can_run);                                           \
  CpuFeatureScope feature_scope(&masm, feature,           \
                                CpuFeatureScope::kDontCheckSupported)

#ifdef USE_SIMULATOR

// The simulator can always run the code even when IsSupported(f) is false.
#define CAN_RUN() true

// Run tests with the simulator.
#define SETUP_SIZE(buf_size)                                                  \
  Isolate* isolate = CcTest::i_isolate();                                     \
  HandleScope scope(isolate);                                                 \
  CHECK_NOT_NULL(isolate);                                                    \
  auto owned_buf =                                                            \
      AllocateAssemblerBuffer(buf_size, nullptr, JitPermission::kNoJit);      \
  MacroAssembler masm(isolate, v8::internal::CodeObjectRequired::kYes,        \
                      ExternalAssemblerBuffer(owned_buf->start(), buf_size)); \
  Decoder<DispatchingDecoderVisitor>* decoder =                               \
      new Decoder<DispatchingDecoderVisitor>();                               \
  Simulator simulator(decoder);                                               \
  std::unique_ptr<PrintDisassembler> pdis;                                    \
  RegisterDump core;                                                          \
  HandleScope handle_scope(isolate);                                          \
  Handle<Code> code;                                                          \
  if (i::v8_flags.trace_sim) {                                                \
    pdis.reset(new PrintDisassembler(stdout));                                \
    decoder->PrependVisitor(pdis.get());                                      \
  }

// Reset the assembler and simulator, so that instructions can be generated,
// but don't actually emit any code. This can be used by tests that need to
// emit instructions at the start of the buffer. Note that START_AFTER_RESET
// must be called before any callee-saved register is modified, and before an
// END is encountered.
//
// Most tests should call START, rather than call RESET directly.
#define RESET()                                                                \
  __ Reset();                                                                  \
  simulator.ResetState();

#define START_AFTER_RESET()                                                    \
  __ PushCalleeSavedRegisters();                                               \
  __ Debug("Start test.", __LINE__, TRACE_ENABLE | LOG_ALL);

#define START()                                                                \
  RESET();                                                                     \
  START_AFTER_RESET();

#define RUN() \
  simulator.RunFrom(reinterpret_cast<Instruction*>(code->instruction_start()))

#define END()                                                                  \
  __ Debug("End test.", __LINE__, TRACE_DISABLE | LOG_ALL);                    \
  core.Dump(&masm);                                                            \
  __ PopCalleeSavedRegisters();                                                \
  __ Ret();                                                                    \
  {                                                                            \
    CodeDesc desc;                                                             \
    __ GetCode(masm.isolate(), &desc);                                         \
    code = Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build(); \
    if (v8_flags.print_code) Print(*code);                                     \
  }

#else  // ifdef USE_SIMULATOR.

#define CAN_RUN() can_run

// Run the test on real hardware or models.
#define SETUP_SIZE(buf_size)                                           \
  Isolate* isolate = CcTest::i_isolate();                              \
  HandleScope scope(isolate);                                          \
  CHECK_NOT_NULL(isolate);                                             \
  auto owned_buf = AllocateAssemblerBuffer(buf_size);                  \
  MacroAssembler masm(isolate, v8::internal::CodeObjectRequired::kYes, \
                      owned_buf->CreateView());                        \
  HandleScope handle_scope(isolate);                                   \
  Handle<Code> code;                                                   \
  RegisterDump core;

#define RESET()                                                \
  __ Reset();                                                  \
  __ CodeEntry();                                              \
  /* Reset the machine state (like simulator.ResetState()). */ \
  __ Msr(NZCV, xzr);                                           \
  __ Msr(FPCR, xzr);

#define START_AFTER_RESET()                                                    \
  __ PushCalleeSavedRegisters();

#define START() \
  RESET();      \
  START_AFTER_RESET();

#define RUN()                                                  \
  {                                                            \
    /* Reset the scope and thus make the buffer executable. */ \
    auto f = GeneratedCode<void>::FromCode(isolate, *code);    \
    f.Call();                                                  \
  }

#define END()                                                                  \
  core.Dump(&masm);                                                            \
  __ PopCalleeSavedRegisters();                                                \
  __ Ret();                                                                    \
  {                                                                            \
    CodeDesc desc;                                                             \
    __ GetCode(masm.isolate(), &desc);                                         \
    code = Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build(); \
    if (v8_flags.print_code) Print(*code);                                     \
  }

#endif  // ifdef USE_SIMULATOR.

#define CHECK_EQUAL_NZCV(expected)                                            \
  CHECK(EqualNzcv(expected, core.flags_nzcv()))

#define CHECK_EQUAL_REGISTERS(expected) \
  CHECK(EqualV8Registers(&expected, &core))

#define CHECK_EQUAL_32(expected, result)                                      \
  CHECK(Equal32(static_cast<uint32_t>(expected), &core, result))

#define CHECK_EQUAL_FP32(expected, result)                                    \
  CHECK(EqualFP32(expected, &core, result))

#define CHECK_EQUAL_64(expected, result)                                      \
  CHECK(Equal64(expected, &core, result))

#define CHECK_FULL_HEAP_OBJECT_IN_REGISTER(expected, result) \
  CHECK(Equal64((*expected).ptr(), &core, result))

#define CHECK_NOT_ZERO_AND_NOT_EQUAL_64(reg0, reg1) \
  {                                                 \
    int64_t value0 = core.xreg(reg0.code());        \
    int64_t value1 = core.xreg(reg1.code());        \
    CHECK_NE(0, value0);                            \
    CHECK_NE(0, value1);                            \
    CHECK_NE(value0, value1);                       \
  }

#define CHECK_EQUAL_FP64(expected, result)                                    \
  CHECK(EqualFP64(expected, &core, result))

// Expected values for 128-bit comparisons are passed as two 64-bit values,
// where expected_h (high) is <127:64> and expected_l (low) is <63:0>.
#define CHECK_EQUAL_128(expected_h, expected_l, result) \
  CHECK(Equal128(expected_h, expected_l, &core, result))

#ifdef DEBUG
#define CHECK_CONSTANT_POOL_SIZE(expected) \
  CHECK_EQ(expected, __ GetConstantPoolEntriesSizeForTesting())
#else
#define CHECK_CONSTANT_POOL_SIZE(expected) ((void)0)
#endif

TEST(stack_ops) {
  INIT_V8();
  SETUP();

  START();
  // save sp.
  __ Mov(x29, sp);

  // Set the sp to a known value.
  __ Mov(x16, 0x1000);
  __ Mov(sp, x16);
  __ Mov(x0, sp);

  // Add immediate to the sp, and move the result to a normal register.
  __ Add(sp, sp, Operand(0x50));
  __ Mov(x1, sp);

  // Add extended to the sp, and move the result to a normal register.
  __ Mov(x17, 0xFFF);
  __ Add(sp, sp, Operand(x17, SXTB));
  __ Mov(x2, sp);

  // Create an sp using a logical instruction, and move to normal register.
  __ Orr(sp, xzr, Operand(0x1FFF));
  __ Mov(x3, sp);

  // Write wsp using a logical instruction.
  __ Orr(wsp, wzr, Operand(0xFFFFFFF8L));
  __ Mov(x4, sp);

  // Write sp, and read back wsp.
  __ Orr(sp, xzr, Operand(0xFFFFFFF8L));
  __ Mov(w5, wsp);

  //  restore sp.
  __ Mov(sp, x29);
  END();

  RUN();

  CHECK_EQUAL_64(0x1000, x0);
  CHECK_EQUAL_64(0x1050, x1);
  CHECK_EQUAL_64(0x104F, x2);
  CHECK_EQUAL_64(0x1FFF, x3);
  CHECK_EQUAL_64(0xFFFFFFF8, x4);
  CHECK_EQUAL_64(0xFFFFFFF8, x5);
}

TEST(mvn) {
  INIT_V8();
  SETUP();

  START();
  __ Mvn(w0, 0xFFF);
  __ Mvn(x1, 0xFFF);
  __ Mvn(w2, Operand(w0, LSL, 1));
  __ Mvn(x3, Operand(x1, LSL, 2));
  __ Mvn(w4, Operand(w0, LSR, 3));
  __ Mvn(x5, Operand(x1, LSR, 4));
  __ Mvn(w6, Operand(w0, ASR, 11));
  __ Mvn(x7, Operand(x1, ASR, 12));
  __ Mvn(w8, Operand(w0, ROR, 13));
  __ Mvn(x9, Operand(x1, ROR, 14));
  __ Mvn(w10, Operand(w2, UXTB));
  __ Mvn(x11, Operand(x2, SXTB, 1));
  __ Mvn(w12, Operand(w2, UXTH, 2));
  __ Mvn(x13, Operand(x2, SXTH, 3));
  __ Mvn(x14, Operand(w2, UXTW, 4));
  __ Mvn(x15, Operand(w2, SXTW, 4));
  END();

  RUN();

  CHECK_EQUAL_64(0xFFFFF000, x0);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFF000UL, x1);
  CHECK_EQUAL_64(0x00001FFF, x2);
  CHECK_EQUAL_64(0x0000000000003FFFUL, x3);
  CHECK_EQUAL_64(0xE00001FF, x4);
  CHECK_EQUAL_64(0xF0000000000000FFUL, x5);
  CHECK_EQUAL_64(0x00000001, x6);
  CHECK_EQUAL_64(0x0, x7);
  CHECK_EQUAL_64(0x7FF80000, x8);
  CHECK_EQUAL_64(0x3FFC000000000000UL, x9);
  CHECK_EQUAL_64(0xFFFFFF00, x10);
  CHECK_EQUAL_64(0x0000000000000001UL, x11);
  CHECK_EQUAL_64(0xFFFF8003, x12);
  CHECK_EQUAL_64(0xFFFFFFFFFFFF0007UL, x13);
  CHECK_EQUAL_64(0xFFFFFFFFFFFE000FUL, x14);
  CHECK_EQUAL_64(0xFFFFFFFFFFFE000FUL, x15);
}

TEST(mov) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x0, 0xFFFFFFFFFFFFFFFFL);
  __ Mov(x1, 0xFFFFFFFFFFFFFFFFL);
  __ Mov(x2, 0xFFFFFFFFFFFFFFFFL);
  __ Mov(x3, 0xFFFFFFFFFFFFFFFFL);

  __ Mov(x0, 0x0123456789ABCDEFL);

  __ movz(x1, 0xABCDLL << 16);
  __ movk(x2, 0xABCDLL << 32);
  __ movn(x3, 0xABCDLL << 48);

  __ Mov(x4, 0x0123456789ABCDEFL);
  __ Mov(x5, x4);

  __ Mov(w6, -1);

  // Test that moves back to the same register have the desired effect. This
  // is a no-op for X registers, and a truncation for W registers.
  __ Mov(x7, 0x0123456789ABCDEFL);
  __ Mov(x7, x7);
  __ Mov(x8, 0x0123456789ABCDEFL);
  __ Mov(w8, w8);
  __ Mov(x9, 0x0123456789ABCDEFL);
  __ Mov(x9, Operand(x9));
  __ Mov(x10, 0x0123456789ABCDEFL);
  __ Mov(w10, Operand(w10));

  __ Mov(w11, 0xFFF);
  __ Mov(x12, 0xFFF);
  __ Mov(w13, Operand(w11, LSL, 1));
  __ Mov(x14, Operand(x12, LSL, 2));
  __ Mov(w15, Operand(w11, LSR, 3));
  __ Mov(x28, Operand(x12, LSR, 4));
  __ Mov(w19, Operand(w11, ASR, 11));
  __ Mov(x20, Operand(x12, ASR, 12));
  __ Mov(w21, Operand(w11, ROR, 13));
  __ Mov(x22, Operand(x12, ROR, 14));
  __ Mov(w23, Operand(w13, UXTB));
  __ Mov(x24, Operand(x13, SXTB, 1));
  __ Mov(w25, Operand(w13, UXTH, 2));
  __ Mov(x26, Operand(x13, SXTH, 3));
  __ Mov(x27, Operand(w13, UXTW, 4));
  END();

  RUN();

  CHECK_EQUAL_64(0x0123456789ABCDEFL, x0);
  CHECK_EQUAL_64(0x00000000ABCD0000L, x1);
  CHECK_EQUAL_64(0xFFFFABCDFFFFFFFFL, x2);
  CHECK_EQUAL_64(0x5432FFFFFFFFFFFFL, x3);
  CHECK_EQUAL_64(x4, x5);
  CHECK_EQUAL_32(-1, w6);
  CHECK_EQUAL_64(0x0123456789ABCDEFL, x7);
  CHECK_EQUAL_32(0x89ABCDEFL, w8);
  CHECK_EQUAL_64(0x0123456789ABCDEFL, x9);
  CHECK_EQUAL_32(0x89ABCDEFL, w10);
  CHECK_EQUAL_64(0x00000FFF, x11);
  CHECK_EQUAL_64(0x0000000000000FFFUL, x12);
  CHECK_EQUAL_64(0x00001FFE, x13);
  CHECK_EQUAL_64(0x0000000000003FFCUL, x14);
  CHECK_EQUAL_64(0x000001FF, x15);
  CHECK_EQUAL_64(0x00000000000000FFUL, x28);
  CHECK_EQUAL_64(0x00000001, x19);
  CHECK_EQUAL_64(0x0, x20);
  CHECK_EQUAL_64(0x7FF80000, x21);
  CHECK_EQUAL_64(0x3FFC000000000000UL, x22);
  CHECK_EQUAL_64(0x000000FE, x23);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFCUL, x24);
  CHECK_EQUAL_64(0x00007FF8, x25);
  CHECK_EQUAL_64(0x000000000000FFF0UL, x26);
  CHECK_EQUAL_64(0x000000000001FFE0UL, x27);
}

TEST(move_pair) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x0, 0xabababab);
  __ Mov(x1, 0xbabababa);
  __ Mov(x2, 0x12341234);
  __ Mov(x3, 0x43214321);

  // No overlap:
  //  x4 <- x0
  //  x5 <- x1
  __ MovePair(x4, x0, x5, x1);

  // Overlap but we can swap moves:
  //  x2 <- x0
  //  x6 <- x2
  __ MovePair(x2, x0, x6, x2);

  // Overlap but can be done:
  //  x7 <- x3
  //  x3 <- x0
  __ MovePair(x7, x3, x3, x0);

  // Swap.
  //  x0 <- x1
  //  x1 <- x0
  __ MovePair(x0, x1, x1, x0);

  END();

  RUN();

  //  x4 <- x0
  //  x5 <- x1
  CHECK_EQUAL_64(0xabababab, x4);
  CHECK_EQUAL_64(0xbabababa, x5);

  //  x2 <- x0
  //  x6 <- x2
  CHECK_EQUAL_64(0xabababab, x2);
  CHECK_EQUAL_64(0x12341234, x6);

  //  x7 <- x3
  //  x3 <- x0
  CHECK_EQUAL_64(0x43214321, x7);
  CHECK_EQUAL_64(0xabababab, x3);

  // x0 and x1 should be swapped.
  CHECK_EQUAL_64(0xbabababa, x0);
  CHECK_EQUAL_64(0xabababab, x1);
}

TEST(mov_imm_w) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(w0, 0xFFFFFFFFL);
  __ Mov(w1, 0xFFFF1234L);
  __ Mov(w2, 0x1234FFFFL);
  __ Mov(w3, 0x00000000L);
  __ Mov(w4, 0x00001234L);
  __ Mov(w5, 0x12340000L);
  __ Mov(w6, 0x12345678L);
  __ Mov(w7, (int32_t)0x80000000);
  __ Mov(w8, (int32_t)0xFFFF0000);
  __ Mov(w9, kWMinInt);
  END();

  RUN();

  CHECK_EQUAL_64(0xFFFFFFFFL, x0);
  CHECK_EQUAL_64(0xFFFF1234L, x1);
  CHECK_EQUAL_64(0x1234FFFFL, x2);
  CHECK_EQUAL_64(0x00000000L, x3);
  CHECK_EQUAL_64(0x00001234L, x4);
  CHECK_EQUAL_64(0x12340000L, x5);
  CHECK_EQUAL_64(0x12345678L, x6);
  CHECK_EQUAL_64(0x80000000L, x7);
  CHECK_EQUAL_64(0xFFFF0000L, x8);
  CHECK_EQUAL_32(kWMinInt, w9);
}

TEST(mov_imm_x) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x0, 0xFFFFFFFFFFFFFFFFL);
  __ Mov(x1, 0xFFFFFFFFFFFF1234L);
  __ Mov(x2, 0xFFFFFFFF12345678L);
  __ Mov(x3, 0xFFFF1234FFFF5678L);
  __ Mov(x4, 0x1234FFFFFFFF5678L);
  __ Mov(x5, 0x1234FFFF5678FFFFL);
  __ Mov(x6, 0x12345678FFFFFFFFL);
  __ Mov(x7, 0x1234FFFFFFFFFFFFL);
  __ Mov(x8, 0x123456789ABCFFFFL);
  __ Mov(x9, 0x12345678FFFF9ABCL);
  __ Mov(x10, 0x1234FFFF56789ABCL);
  __ Mov(x11, 0xFFFF123456789ABCL);
  __ Mov(x12, 0x0000000000000000L);
  __ Mov(x13, 0x0000000000001234L);
  __ Mov(x14, 0x0000000012345678L);
  __ Mov(x15, 0x0000123400005678L);
  __ Mov(x30, 0x1234000000005678L);
  __ Mov(x19, 0x1234000056780000L);
  __ Mov(x20, 0x1234567800000000L);
  __ Mov(x21, 0x1234000000000000L);
  __ Mov(x22, 0x123456789ABC0000L);
  __ Mov(x23, 0x1234567800009ABCL);
  __ Mov(x24, 0x1234000056789ABCL);
  __ Mov(x25, 0x0000123456789ABCL);
  __ Mov(x26, 0x123456789ABCDEF0L);
  __ Mov(x27, 0xFFFF000000000001L);
  __ Mov(x28, 0x8000FFFF00000000L);
  END();

  RUN();

  CHECK_EQUAL_64(0xFFFFFFFFFFFF1234L, x1);
  CHECK_EQUAL_64(0xFFFFFFFF12345678L, x2);
  CHECK_EQUAL_64(0xFFFF1234FFFF5678L, x3);
  CHECK_EQUAL_64(0x1234FFFFFFFF5678L, x4);
  CHECK_EQUAL_64(0x1234FFFF5678FFFFL, x5);
  CHECK_EQUAL_64(0x12345678FFFFFFFFL, x6);
  CHECK_EQUAL_64(0x1234FFFFFFFFFFFFL, x7);
  CHECK_EQUAL_64(0x123456789ABCFFFFL, x8);
  CHECK_EQUAL_64(0x12345678FFFF9ABCL, x9);
  CHECK_EQUAL_64(0x1234FFFF56789ABCL, x10);
  CHECK_EQUAL_64(0xFFFF123456789ABCL, x11);
  CHECK_EQUAL_64(0x0000000000000000L, x12);
  CHECK_EQUAL_64(0x0000000000001234L, x13);
  CHECK_EQUAL_64(0x0000000012345678L, x14);
  CHECK_EQUAL_64(0x0000123400005678L, x15);
  CHECK_EQUAL_64(0x1234000000005678L, x30);
  CHECK_EQUAL_64(0x1234000056780000L, x19);
  CHECK_EQUAL_64(0x1234567800000000L, x20);
  CHECK_EQUAL_64(0x1234000000000000L, x21);
  CHECK_EQUAL_64(0x123456789ABC0000L, x22);
  CHECK_EQUAL_64(0x1234567800009ABCL, x23);
  CHECK_EQUAL_64(0x1234000056789ABCL, x24);
  CHECK_EQUAL_64(0x0000123456789ABCL, x25);
  CHECK_EQUAL_64(0x123456789ABCDEF0L, x26);
  CHECK_EQUAL_64(0xFFFF000000000001L, x27);
  CHECK_EQUAL_64(0x8000FFFF00000000L, x28);
}

TEST(orr) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x0, 0xF0F0);
  __ Mov(x1, 0xF00000FF);

  __ Orr(x2, x0, Operand(x1));
  __ Orr(w3, w0, Operand(w1, LSL, 28));
  __ Orr(x4, x0, Operand(x1, LSL, 32));
  __ Orr(x5, x0, Operand(x1, LSR, 4));
  __ Orr(w6, w0, Operand(w1, ASR, 4));
  __ Orr(x7, x0, Operand(x1, ASR, 4));
  __ Orr(w8, w0, Operand(w1, ROR, 12));
  __ Orr(x9, x0, Operand(x1, ROR, 12));
  __ Orr(w10, w0, Operand(0xF));
  __ Orr(x11, x0, Operand(0xF0000000F0000000L));
  END();

  RUN();

  CHECK_EQUAL_64(0xF000F0FF, x2);
  CHECK_EQUAL_64(0xF000F0F0, x3);
  CHECK_EQUAL_64(0xF00000FF0000F0F0L, x4);
  CHECK_EQUAL_64(0x0F00F0FF, x5);
  CHECK_EQUAL_64(0xFF00F0FF, x6);
  CHECK_EQUAL_64(0x0F00F0FF, x7);
  CHECK_EQUAL_64(0x0FFFF0F0, x8);
  CHECK_EQUAL_64(0x0FF00000000FF0F0L, x9);
  CHECK_EQUAL_64(0xF0FF, x10);
  CHECK_EQUAL_64(0xF0000000F000F0F0L, x11);
}

TEST(orr_extend) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x0, 1);
  __ Mov(x1, 0x8000000080008080UL);
  __ Orr(w6, w0, Operand(w1, UXTB));
  __ Orr(x7, x0, Operand(x1, UXTH, 1));
  __ Orr(w8, w0, Operand(w1, UXTW, 2));
  __ Orr(x9, x0, Operand(x1, UXTX, 3));
  __ Orr(w10, w0, Operand(w1, SXTB));
  __ Orr(x11, x0, Operand(x1, SXTH, 1));
  __ Orr(x12, x0, Operand(x1, SXTW, 2));
  __ Orr(x13, x0, Operand(x1, SXTX, 3));
  END();

  RUN();

  CHECK_EQUAL_64(0x00000081, x6);
  CHECK_EQUAL_64(0x00010101, x7);
  CHECK_EQUAL_64(0x00020201, x8);
  CHECK_EQUAL_64(0x0000000400040401UL, x9);
  CHECK_EQUAL_64(0x00000000FFFFFF81UL, x10);
  CHECK_EQUAL_64(0xFFFFFFFFFFFF0101UL, x11);
  CHECK_EQUAL_64(0xFFFFFFFE00020201UL, x12);
  CHECK_EQUAL_64(0x0000000400040401UL, x13);
}

TEST(bitwise_wide_imm) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x0, 0);
  __ Mov(x1, 0xF0F0F0F0F0F0F0F0UL);

  __ Orr(x10, x0, Operand(0x1234567890ABCDEFUL));
  __ Orr(w11, w1, Operand(0x90ABCDEF));

  __ Orr(w12, w0, kWMinInt);
  __ Eor(w13, w0, kWMinInt);
  END();

  RUN();

  CHECK_EQUAL_64(0, x0);
  CHECK_EQUAL_64(0xF0F0F0F0F0F0F0F0UL, x1);
  CHECK_EQUAL_64(0x1234567890ABCDEFUL, x10);
  CHECK_EQUAL_64(0xF0FBFDFFUL, x11);
  CHECK_EQUAL_32(kWMinInt, w12);
  CHECK_EQUAL_32(kWMinInt, w13);
}

TEST(orn) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x0, 0xF0F0);
  __ Mov(x1, 0xF00000FF);

  __ Orn(x2, x0, Operand(x1));
  __ Orn(w3, w0, Operand(w1, LSL, 4));
  __ Orn(x4, x0, Operand(x1, LSL, 4));
  __ Orn(x5, x0, Operand(x1, LSR, 1));
  __ Orn(w6, w0, Operand(w1, ASR, 1));
  __ Orn(x7, x0, Operand(x1, ASR, 1));
  __ Orn(w8, w0, Operand(w1, ROR, 16));
  __ Orn(x9, x0, Operand(x1, ROR, 16));
  __ Orn(w10, w0, Operand(0xFFFF));
  __ Orn(x11, x0, Operand(0xFFFF0000FFFFL));
  END();

  RUN();

  CHECK_EQUAL_64(0xFFFFFFFF0FFFFFF0L, x2);
  CHECK_EQUAL_64(0xFFFFF0FF, x3);
  CHECK_EQUAL_64(0xFFFFFFF0FFFFF0FFL, x4);
  CHECK_EQUAL_64(0xFFFFFFFF87FFFFF0L, x5);
  CHECK_EQUAL_64(0x07FFFFF0, x6);
  CHECK_EQUAL_64(0xFFFFFFFF87FFFFF0L, x7);
  CHECK_EQUAL_64(0xFF00FFFF, x8);
  CHECK_EQUAL_64(0xFF00FFFFFFFFFFFFL, x9);
  CHECK_EQUAL_64(0xFFFFF0F0, x10);
  CHECK_EQUAL_64(0xFFFF0000FFFFF0F0L, x11);
}

TEST(orn_extend) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x0, 1);
  __ Mov(x1, 0x8000000080008081UL);
  __ Orn(w6, w0, Operand(w1, UXTB));
  __ Orn(x7, x0, Operand(x1, UXTH, 1));
  __ Orn(w8, w0, Operand(w1, UXTW, 2));
  __ Orn(x9, x0, Operand(x1, UXTX, 3));
  __ Orn(w10, w0, Operand(w1, SXTB));
  __ Orn(x11, x0, Operand(x1, SXTH, 1));
  __ Orn(x12, x0, Operand(x1, SXTW, 2));
  __ Orn(x13, x0, Operand(x1, SXTX, 3));
  END();

  RUN();

  CHECK_EQUAL_64(0xFFFFFF7F, x6);
  CHECK_EQUAL_64(0xFFFFFFFFFFFEFEFDUL, x7);
  CHECK_EQUAL_64(0xFFFDFDFB, x8);
  CHECK_EQUAL_64(0xFFFFFFFBFFFBFBF7UL, x9);
  CHECK_EQUAL_64(0x0000007F, x10);
  CHECK_EQUAL_64(0x0000FEFD, x11);
  CHECK_EQUAL_64(0x00000001FFFDFDFBUL, x12);
  CHECK_EQUAL_64(0xFFFFFFFBFFFBFBF7UL, x13);
}

TEST(and_) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x0, 0xFFF0);
  __ Mov(x1, 0xF00000FF);

  __ And(x2, x0, Operand(x1));
  __ And(w3, w0, Operand(w1, LSL, 4));
  __ And(x4, x0, Operand(x1, LSL, 4));
  __ And(x5, x0, Operand(x1, LSR, 1));
  __ And(w6, w0, Operand(w1, ASR, 20));
  __ And(x7, x0, Operand(x1, ASR, 20));
  __ And(w8, w0, Operand(w1, ROR, 28));
  __ And(x9, x0, Operand(x1, ROR, 28));
  __ And(w10, w0, Operand(0xFF00));
  __ And(x11, x0, Operand(0xFF));
  END();

  RUN();

  CHECK_EQUAL_64(0x000000F0, x2);
  CHECK_EQUAL_64(0x00000FF0, x3);
  CHECK_EQUAL_64(0x00000FF0, x4);
  CHECK_EQUAL_64(0x00000070, x5);
  CHECK_EQUAL_64(0x0000FF00, x6);
  CHECK_EQUAL_64(0x00000F00, x7);
  CHECK_EQUAL_64(0x00000FF0, x8);
  CHECK_EQUAL_64(0x00000000, x9);
  CHECK_EQUAL_64(0x0000FF00, x10);
  CHECK_EQUAL_64(0x000000F0, x11);
}

TEST(and_extend) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x0, 0xFFFFFFFFFFFFFFFFUL);
  __ Mov(x1, 0x8000000080008081UL);
  __ And(w6, w0, Operand(w1, UXTB));
  __ And(x7, x0, Operand(x1, UXTH, 1));
  __ And(w8, w0, Operand(w1, UXTW, 2));
  __ And(x9, x0, Operand(x1, UXTX, 3));
  __ And(w10, w0, Operand(w1, SXTB));
  __ And(x11, x0, Operand(x1, SXTH, 1));
  __ And(x12, x0, Operand(x1, SXTW, 2));
  __ And(x13, x0, Operand(x1, SXTX, 3));
  END();

  RUN();

  CHECK_EQUAL_64(0x00000081, x6);
  CHECK_EQUAL_64(0x00010102, x7);
  CHECK_EQUAL_64(0x00020204, x8);
  CHECK_EQUAL_64(0x0000000400040408UL, x9);
  CHECK_EQUAL_64(0xFFFFFF81, x10);
  CHECK_EQUAL_64(0xFFFFFFFFFFFF0102UL, x11);
  CHECK_EQUAL_64(0xFFFFFFFE00020204UL, x12);
  CHECK_EQUAL_64(0x0000000400040408UL, x13);
}

TEST(ands) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x1, 0xF00000FF);
  __ Ands(w0, w1, Operand(w1));
  END();

  RUN();

  CHECK_EQUAL_NZCV(NFlag);
  CHECK_EQUAL_64(0xF00000FF, x0);

  START();
  __ Mov(x0, 0xFFF0);
  __ Mov(x1, 0xF00000FF);
  __ Ands(w0, w0, Operand(w1, LSR, 4));
  END();

  RUN();

  CHECK_EQUAL_NZCV(ZFlag);
  CHECK_EQUAL_64(0x00000000, x0);

  START();
  __ Mov(x0, 0x8000000000000000L);
  __ Mov(x1, 0x00000001);
  __ Ands(x0, x0, Operand(x1, ROR, 1));
  END();

  RUN();

  CHECK_EQUAL_NZCV(NFlag);
  CHECK_EQUAL_64(0x8000000000000000L, x0);

  START();
  __ Mov(x0, 0xFFF0);
  __ Ands(w0, w0, Operand(0xF));
  END();

  RUN();

  CHECK_EQUAL_NZCV(ZFlag);
  CHECK_EQUAL_64(0x00000000, x0);

  START();
  __ Mov(x0, 0xFF000000);
  __ Ands(w0, w0, Operand(0x80000000));
  END();

  RUN();

  CHECK_EQUAL_NZCV(NFlag);
  CHECK_EQUAL_64(0x80000000, x0);
}

TEST(bic) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x0, 0xFFF0);
  __ Mov(x1, 0xF00000FF);

  __ Bic(x2, x0, Operand(x1));
  __ Bic(w3, w0, Operand(w1, LSL, 4));
  __ Bic(x4, x0, Operand(x1, LSL, 4));
  __ Bic(x5, x0, Operand(x1, LSR, 1));
  __ Bic(w6, w0, Operand(w1, ASR, 20));
  __ Bic(x7, x0, Operand(x1, ASR, 20));
  __ Bic(w8, w0, Operand(w1, ROR, 28));
  __ Bic(x9, x0, Operand(x1, ROR, 24));
  __ Bic(x10, x0, Operand(0x1F));
  __ Bic(x11, x0, Operand(0x100));

  // Test bic into sp when the constant cannot be encoded in the immediate
  // field.
  // Use x20 to preserve sp. We check for the result via x21 because the
  // test infrastructure requires that sp be restored to its original value.
  __ Mov(x20, sp);
  __ Mov(x0, 0xFFFFFF);
  __ Bic(sp, x0, Operand(0xABCDEF));
  __ Mov(x21, sp);
  __ Mov(sp, x20);
  END();

  RUN();

  CHECK_EQUAL_64(0x0000FF00, x2);
  CHECK_EQUAL_64(0x0000F000, x3);
  CHECK_EQUAL_64(0x0000F000, x4);
  CHECK_EQUAL_64(0x0000FF80, x5);
  CHECK_EQUAL_64(0x000000F0, x6);
  CHECK_EQUAL_64(0x0000F0F0, x7);
  CHECK_EQUAL_64(0x0000F000, x8);
  CHECK_EQUAL_64(0x0000FF00, x9);
  CHECK_EQUAL_64(0x0000FFE0, x10);
  CHECK_EQUAL_64(0x0000FEF0, x11);

  CHECK_EQUAL_64(0x543210, x21);
}

TEST(bic_extend) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x0, 0xFFFFFFFFFFFFFFFFUL);
  __ Mov(x1, 0x8000000080008081UL);
  __ Bic(w6, w0, Operand(w1, UXTB));
  __ Bic(x7, x0, Operand(x1, UXTH, 1));
  __ Bic(w8, w0, Operand(w1, UXTW, 2));
  __ Bic(x9, x0, Operand(x1, UXTX, 3));
  __ Bic(w10, w0, Operand(w1, SXTB));
  __ Bic(x11, x0, Operand(x1, SXTH, 1));
  __ Bic(x12, x0, Operand(x1, SXTW, 2));
  __ Bic(x13, x0, Operand(x1, SXTX, 3));
  END();

  RUN();

  CHECK_EQUAL_64(0xFFFFFF7E, x6);
  CHECK_EQUAL_64(0xFFFFFFFFFFFEFEFDUL, x7);
  CHECK_EQUAL_64(0xFFFDFDFB, x8);
  CHECK_EQUAL_64(0xFFFFFFFBFFFBFBF7UL, x9);
  CHECK_EQUAL_64(0x0000007E, x10);
  CHECK_EQUAL_64(0x0000FEFD, x11);
  CHECK_EQUAL_64(0x00000001FFFDFDFBUL, x12);
  CHECK_EQUAL_64(0xFFFFFFFBFFFBFBF7UL, x13);
}

TEST(bics) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x1, 0xFFFF);
  __ Bics(w0, w1, Operand(w1));
  END();

  RUN();

  CHECK_EQUAL_NZCV(ZFlag);
  CHECK_EQUAL_64(0x00000000, x0);

  START();
  __ Mov(x0, 0xFFFFFFFF);
  __ Bics(w0, w0, Operand(w0, LSR, 1));
  END();

  RUN();

  CHECK_EQUAL_NZCV(NFlag);
  CHECK_EQUAL_64(0x80000000, x0);

  START();
  __ Mov(x0, 0x8000000000000000L);
  __ Mov(x1, 0x00000001);
  __ Bics(x0, x0, Operand(x1, ROR, 1));
  END();

  RUN();

  CHECK_EQUAL_NZCV(ZFlag);
  CHECK_EQUAL_64(0x00000000, x0);

  START();
  __ Mov(x0, 0xFFFFFFFFFFFFFFFFL);
  __ Bics(x0, x0, Operand(0x7FFFFFFFFFFFFFFFL));
  END();

  RUN();

  CHECK_EQUAL_NZCV(NFlag);
  CHECK_EQUAL_64(0x8000000000000000L, x0);

  START();
  __ Mov(w0, 0xFFFF0000);
  __ Bics(w0, w0, Operand(0xFFFFFFF0));
  END();

  RUN();

  CHECK_EQUAL_NZCV(ZFlag);
  CHECK_EQUAL_64(0x00000000, x0);
}

TEST(eor) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x0, 0xFFF0);
  __ Mov(x1, 0xF00000FF);

  __ Eor(x2, x0, Operand(x1));
  __ Eor(w3, w0, Operand(w1, LSL, 4));
  __ Eor(x4, x0, Operand(x1, LSL, 4));
  __ Eor(x5, x0, Operand(x1, LSR, 1));
  __ Eor(w6, w0, Operand(w1, ASR, 20));
  __ Eor(x7, x0, Operand(x1, ASR, 20));
  __ Eor(w8, w0, Operand(w1, ROR, 28));
  __ Eor(x9, x0, Operand(x1, ROR, 28));
  __ Eor(w10, w0, Operand(0xFF00FF00));
  __ Eor(x11, x0, Operand(0xFF00FF00FF00FF00L));
  END();

  RUN();

  CHECK_EQUAL_64(0xF000FF0F, x2);
  CHECK_EQUAL_64(0x0000F000, x3);
  CHECK_EQUAL_64(0x0000000F0000F000L, x4);
  CHECK_EQUAL_64(0x7800FF8F, x5);
  CHECK_EQUAL_64(0xFFFF00F0, x6);
  CHECK_EQUAL_64(0x0000F0F0, x7);
  CHECK_EQUAL_64(0x0000F00F, x8);
  CHECK_EQUAL_64(0x00000FF00000FFFFL, x9);
  CHECK_EQUAL_64(0xFF0000F0, x10);
  CHECK_EQUAL_64(0xFF00FF00FF0000F0L, x11);
}

TEST(eor_extend) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x0, 0x1111111111111111UL);
  __ Mov(x1, 0x8000000080008081UL);
  __ Eor(w6, w0, Operand(w1, UXTB));
  __ Eor(x7, x0, Operand(x1, UXTH, 1));
  __ Eor(w8, w0, Operand(w1, UXTW, 2));
  __ Eor(x9, x0, Operand(x1, UXTX, 3));
  __ Eor(w10, w0, Operand(w1, SXTB));
  __ Eor(x11, x0, Operand(x1, SXTH, 1));
  __ Eor(x12, x0, Operand(x1, SXTW, 2));
  __ Eor(x13, x0, Operand(x1, SXTX, 3));
  END();

  RUN();

  CHECK_EQUAL_64(0x11111190, x6);
  CHECK_EQUAL_64(0x1111111111101013UL, x7);
  CHECK_EQUAL_64(0x11131315, x8);
  CHECK_EQUAL_64(0x1111111511151519UL, x9);
  CHECK_EQUAL_64(0xEEEEEE90, x10);
  CHECK_EQUAL_64(0xEEEEEEEEEEEE1013UL, x11);
  CHECK_EQUAL_64(0xEEEEEEEF11131315UL, x12);
  CHECK_EQUAL_64(0x1111111511151519UL, x13);
}

TEST(eon) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x0, 0xFFF0);
  __ Mov(x1, 0xF00000FF);

  __ Eon(x2, x0, Operand(x1));
  __ Eon(w3, w0, Operand(w1, LSL, 4));
  __ Eon(x4, x0, Operand(x1, LSL, 4));
  __ Eon(x5, x0, Operand(x1, LSR, 1));
  __ Eon(w6, w0, Operand(w1, ASR, 20));
  __ Eon(x7, x0, Operand(x1, ASR, 20));
  __ Eon(w8, w0, Operand(w1, ROR, 28));
  __ Eon(x9, x0, Operand(x1, ROR, 28));
  __ Eon(w10, w0, Operand(0x03C003C0));
  __ Eon(x11, x0, Operand(0x0000100000001000L));
  END();

  RUN();

  CHECK_EQUAL_64(0xFFFFFFFF0FFF00F0L, x2);
  CHECK_EQUAL_64(0xFFFF0FFF, x3);
  CHECK_EQUAL_64(0xFFFFFFF0FFFF0FFFL, x4);
  CHECK_EQUAL_64(0xFFFFFFFF87FF0070L, x5);
  CHECK_EQUAL_64(0x0000FF0F, x6);
  CHECK_EQUAL_64(0xFFFFFFFFFFFF0F0FL, x7);
  CHECK_EQUAL_64(0xFFFF0FF0, x8);
  CHECK_EQUAL_64(0xFFFFF00FFFFF0000L, x9);
  CHECK_EQUAL_64(0xFC3F03CF, x10);
  CHECK_EQUAL_64(0xFFFFEFFFFFFF100FL, x11);
}

TEST(eon_extend) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x0, 0x1111111111111111UL);
  __ Mov(x1, 0x8000000080008081UL);
  __ Eon(w6, w0, Operand(w1, UXTB));
  __ Eon(x7, x0, Operand(x1, UXTH, 1));
  __ Eon(w8, w0, Operand(w1, UXTW, 2));
  __ Eon(x9, x0, Operand(x1, UXTX, 3));
  __ Eon(w10, w0, Operand(w1, SXTB));
  __ Eon(x11, x0, Operand(x1, SXTH, 1));
  __ Eon(x12, x0, Operand(x1, SXTW, 2));
  __ Eon(x13, x0, Operand(x1, SXTX, 3));
  END();

  RUN();

  CHECK_EQUAL_64(0xEEEEEE6F, x6);
  CHECK_EQUAL_64(0xEEEEEEEEEEEFEFECUL, x7);
  CHECK_EQUAL_64(0xEEECECEA, x8);
  CHECK_EQUAL_64(0xEEEEEEEAEEEAEAE6UL, x9);
  CHECK_EQUAL_64(0x1111116F, x10);
  CHECK_EQUAL_64(0x111111111111EFECUL, x11);
  CHECK_EQUAL_64(0x11111110EEECECEAUL, x12);
  CHECK_EQUAL_64(0xEEEEEEEAEEEAEAE6UL, x13);
}

TEST(mul) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x16, 0);
  __ Mov(x17, 1);
  __ Mov(x15, 0xFFFFFFFF);
  __ Mov(x19, 0xFFFFFFFFFFFFFFFFUL);

  __ Mul(w0, w16, w16);
  __ Mul(w1, w16, w17);
  __ Mul(w2, w17, w15);
  __ Mul(w3, w15, w19);
  __ Mul(x4, x16, x16);
  __ Mul(x5, x17, x15);
  __ Mul(x6, x15, x19);
  __ Mul(x7, x19, x19);
  __ Smull(x8, w17, w15);
  __ Smull(x9, w15, w15);
  __ Smull(x10, w19, w19);
  __ Mneg(w11, w16, w16);
  __ Mneg(w12, w16, w17);
  __ Mneg(w13, w17, w15);
  __ Mneg(w14, w15, w19);
  __ Mneg(x20, x16, x16);
  __ Mneg(x21, x17, x15);
  __ Mneg(x22, x15, x19);
  __ Mneg(x23, x19, x19);
  END();

  RUN();

  CHECK_EQUAL_64(0, x0);
  CHECK_EQUAL_64(0, x1);
  CHECK_EQUAL_64(0xFFFFFFFF, x2);
  CHECK_EQUAL_64(1, x3);
  CHECK_EQUAL_64(0, x4);
  CHECK_EQUAL_64(0xFFFFFFFF, x5);
  CHECK_EQUAL_64(0xFFFFFFFF00000001UL, x6);
  CHECK_EQUAL_64(1, x7);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFFUL, x8);
  CHECK_EQUAL_64(1, x9);
  CHECK_EQUAL_64(1, x10);
  CHECK_EQUAL_64(0, x11);
  CHECK_EQUAL_64(0, x12);
  CHECK_EQUAL_64(1, x13);
  CHECK_EQUAL_64(0xFFFFFFFF, x14);
  CHECK_EQUAL_64(0, x20);
  CHECK_EQUAL_64(0xFFFFFFFF00000001UL, x21);
  CHECK_EQUAL_64(0xFFFFFFFF, x22);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFFUL, x23);
}

static void SmullHelper(int64_t expected, int64_t a, int64_t b) {
  SETUP();
  START();
  __ Mov(w0, a);
  __ Mov(w1, b);
  __ Smull(x2, w0, w1);
  END();
  RUN();
  CHECK_EQUAL_64(expected, x2);
}

TEST(smull) {
  INIT_V8();
  SmullHelper(0, 0, 0);
  SmullHelper(1, 1, 1);
  SmullHelper(-1, -1, 1);
  SmullHelper(1, -1, -1);
  SmullHelper(0xFFFFFFFF80000000, 0x80000000, 1);
  SmullHelper(0x0000000080000000, 0x00010000, 0x00008000);
}

TEST(madd) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x16, 0);
  __ Mov(x17, 1);
  __ Mov(x28, 0xFFFFFFFF);
  __ Mov(x19, 0xFFFFFFFFFFFFFFFFUL);

  __ Madd(w0, w16, w16, w16);
  __ Madd(w1, w16, w16, w17);
  __ Madd(w2, w16, w16, w28);
  __ Madd(w3, w16, w16, w19);
  __ Madd(w4, w16, w17, w17);
  __ Madd(w5, w17, w17, w28);
  __ Madd(w6, w17, w17, w19);
  __ Madd(w7, w17, w28, w16);
  __ Madd(w8, w17, w28, w28);
  __ Madd(w9, w28, w28, w17);
  __ Madd(w10, w28, w19, w28);
  __ Madd(w11, w19, w19, w19);

  __ Madd(x12, x16, x16, x16);
  __ Madd(x13, x16, x16, x17);
  __ Madd(x14, x16, x16, x28);
  __ Madd(x15, x16, x16, x19);
  __ Madd(x20, x16, x17, x17);
  __ Madd(x21, x17, x17, x28);
  __ Madd(x22, x17, x17, x19);
  __ Madd(x23, x17, x28, x16);
  __ Madd(x24, x17, x28, x28);
  __ Madd(x25, x28, x28, x17);
  __ Madd(x26, x28, x19, x28);
  __ Madd(x27, x19, x19, x19);

  END();

  RUN();

  CHECK_EQUAL_64(0, x0);
  CHECK_EQUAL_64(1, x1);
  CHECK_EQUAL_64(0xFFFFFFFF, x2);
  CHECK_EQUAL_64(0xFFFFFFFF, x3);
  CHECK_EQUAL_64(1, x4);
  CHECK_EQUAL_64(0, x5);
  CHECK_EQUAL_64(0, x6);
  CHECK_EQUAL_64(0xFFFFFFFF, x7);
  CHECK_EQUAL_64(0xFFFFFFFE, x8);
  CHECK_EQUAL_64(2, x9);
  CHECK_EQUAL_64(0, x10);
  CHECK_EQUAL_64(0, x11);

  CHECK_EQUAL_64(0, x12);
  CHECK_EQUAL_64(1, x13);
  CHECK_EQUAL_64(0xFFFFFFFF, x14);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFF, x15);
  CHECK_EQUAL_64(1, x20);
  CHECK_EQUAL_64(0x100000000UL, x21);
  CHECK_EQUAL_64(0, x22);
  CHECK_EQUAL_64(0xFFFFFFFF, x23);
  CHECK_EQUAL_64(0x1FFFFFFFE, x24);
  CHECK_EQUAL_64(0xFFFFFFFE00000002UL, x25);
  CHECK_EQUAL_64(0, x26);
  CHECK_EQUAL_64(0, x27);
}

TEST(msub) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x16, 0);
  __ Mov(x17, 1);
  __ Mov(x28, 0xFFFFFFFF);
  __ Mov(x19, 0xFFFFFFFFFFFFFFFFUL);

  __ Msub(w0, w16, w16, w16);
  __ Msub(w1, w16, w16, w17);
  __ Msub(w2, w16, w16, w28);
  __ Msub(w3, w16, w16, w19);
  __ Msub(w4, w16, w17, w17);
  __ Msub(w5, w17, w17, w28);
  __ Msub(w6, w17, w17, w19);
  __ Msub(w7, w17, w28, w16);
  __ Msub(w8, w17, w28, w28);
  __ Msub(w9, w28, w28, w17);
  __ Msub(w10, w28, w19, w28);
  __ Msub(w11, w19, w19, w19);

  __ Msub(x12, x16, x16, x16);
  __ Msub(x13, x16, x16, x17);
  __ Msub(x14, x16, x16, x28);
  __ Msub(x15, x16, x16, x19);
  __ Msub(x20, x16, x17, x17);
  __ Msub(x21, x17, x17, x28);
  __ Msub(x22, x17, x17, x19);
  __ Msub(x23, x17, x28, x16);
  __ Msub(x24, x17, x28, x28);
  __ Msub(x25, x28, x28, x17);
  __ Msub(x26, x28, x19, x28);
  __ Msub(x27, x19, x19, x19);

  END();

  RUN();

  CHECK_EQUAL_64(0, x0);
  CHECK_EQUAL_64(1, x1);
  CHECK_EQUAL_64(0xFFFFFFFF, x2);
  CHECK_EQUAL_64(0xFFFFFFFF, x3);
  CHECK_EQUAL_64(1, x4);
  CHECK_EQUAL_64(0xFFFFFFFE, x5);
  CHECK_EQUAL_64(0xFFFFFFFE, x6);
  CHECK_EQUAL_64(1, x7);
  CHECK_EQUAL_64(0, x8);
  CHECK_EQUAL_64(0, x9);
  CHECK_EQUAL_64(0xFFFFFFFE, x10);
  CHECK_EQUAL_64(0xFFFFFFFE, x11);

  CHECK_EQUAL_64(0, x12);
  CHECK_EQUAL_64(1, x13);
  CHECK_EQUAL_64(0xFFFFFFFF, x14);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFFUL, x15);
  CHECK_EQUAL_64(1, x20);
  CHECK_EQUAL_64(0xFFFFFFFEUL, x21);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFEUL, x22);
  CHECK_EQUAL_64(0xFFFFFFFF00000001UL, x23);
  CHECK_EQUAL_64(0, x24);
  CHECK_EQUAL_64(0x200000000UL, x25);
  CHECK_EQUAL_64(0x1FFFFFFFEUL, x26);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFEUL, x27);
}

TEST(smulh) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x20, 0);
  __ Mov(x21, 1);
  __ Mov(x22, 0x0000000100000000L);
  __ Mov(x23, 0x12345678);
  __ Mov(x24, 0x0123456789ABCDEFL);
  __ Mov(x25, 0x0000000200000000L);
  __ Mov(x26, 0x8000000000000000UL);
  __ Mov(x27, 0xFFFFFFFFFFFFFFFFUL);
  __ Mov(x28, 0x5555555555555555UL);
  __ Mov(x29, 0xAAAAAAAAAAAAAAAAUL);

  __ Smulh(x0, x20, x24);
  __ Smulh(x1, x21, x24);
  __ Smulh(x2, x22, x23);
  __ Smulh(x3, x22, x24);
  __ Smulh(x4, x24, x25);
  __ Smulh(x5, x23, x27);
  __ Smulh(x6, x26, x26);
  __ Smulh(x7, x26, x27);
  __ Smulh(x8, x27, x27);
  __ Smulh(x9, x28, x28);
  __ Smulh(x10, x28, x29);
  __ Smulh(x11, x29, x29);
  END();

  RUN();

  CHECK_EQUAL_64(0, x0);
  CHECK_EQUAL_64(0, x1);
  CHECK_EQUAL_64(0, x2);
  CHECK_EQUAL_64(0x01234567, x3);
  CHECK_EQUAL_64(0x02468ACF, x4);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFFUL, x5);
  CHECK_EQUAL_64(0x4000000000000000UL, x6);
  CHECK_EQUAL_64(0, x7);
  CHECK_EQUAL_64(0, x8);
  CHECK_EQUAL_64(0x1C71C71C71C71C71UL, x9);
  CHECK_EQUAL_64(0xE38E38E38E38E38EUL, x10);
  CHECK_EQUAL_64(0x1C71C71C71C71C72UL, x11);
}

TEST(smaddl_umaddl) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x17, 1);
  __ Mov(x28, 0xFFFFFFFF);
  __ Mov(x19, 0xFFFFFFFFFFFFFFFFUL);
  __ Mov(x20, 4);
  __ Mov(x21, 0x200000000UL);

  __ Smaddl(x9, w17, w28, x20);
  __ Smaddl(x10, w28, w28, x20);
  __ Smaddl(x11, w19, w19, x20);
  __ Smaddl(x12, w19, w19, x21);
  __ Umaddl(x13, w17, w28, x20);
  __ Umaddl(x14, w28, w28, x20);
  __ Umaddl(x15, w19, w19, x20);
  __ Umaddl(x22, w19, w19, x21);
  END();

  RUN();

  CHECK_EQUAL_64(3, x9);
  CHECK_EQUAL_64(5, x10);
  CHECK_EQUAL_64(5, x11);
  CHECK_EQUAL_64(0x200000001UL, x12);
  CHECK_EQUAL_64(0x100000003UL, x13);
  CHECK_EQUAL_64(0xFFFFFFFE00000005UL, x14);
  CHECK_EQUAL_64(0xFFFFFFFE00000005UL, x15);
  CHECK_EQUAL_64(0x1, x22);
}

TEST(smsubl_umsubl) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x17, 1);
  __ Mov(x28, 0xFFFFFFFF);
  __ Mov(x19, 0xFFFFFFFFFFFFFFFFUL);
  __ Mov(x20, 4);
  __ Mov(x21, 0x200000000UL);

  __ Smsubl(x9, w17, w28, x20);
  __ Smsubl(x10, w28, w28, x20);
  __ Smsubl(x11, w19, w19, x20);
  __ Smsubl(x12, w19, w19, x21);
  __ Umsubl(x13, w17, w28, x20);
  __ Umsubl(x14, w28, w28, x20);
  __ Umsubl(x15, w19, w19, x20);
  __ Umsubl(x22, w19, w19, x21);
  END();

  RUN();

  CHECK_EQUAL_64(5, x9);
  CHECK_EQUAL_64(3, x10);
  CHECK_EQUAL_64(3, x11);
  CHECK_EQUAL_64(0x1FFFFFFFFUL, x12);
  CHECK_EQUAL_64(0xFFFFFFFF00000005UL, x13);
  CHECK_EQUAL_64(0x200000003UL, x14);
  CHECK_EQUAL_64(0x200000003UL, x15);
  CHECK_EQUAL_64(0x3FFFFFFFFUL, x22);
}

TEST(div) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x16, 1);
  __ Mov(x17, 0xFFFFFFFF);
  __ Mov(x30, 0xFFFFFFFFFFFFFFFFUL);
  __ Mov(x19, 0x80000000);
  __ Mov(x20, 0x8000000000000000UL);
  __ Mov(x21, 2);

  __ Udiv(w0, w16, w16);
  __ Udiv(w1, w17, w16);
  __ Sdiv(w2, w16, w16);
  __ Sdiv(w3, w16, w17);
  __ Sdiv(w4, w17, w30);

  __ Udiv(x5, x16, x16);
  __ Udiv(x6, x17, x30);
  __ Sdiv(x7, x16, x16);
  __ Sdiv(x8, x16, x17);
  __ Sdiv(x9, x17, x30);

  __ Udiv(w10, w19, w21);
  __ Sdiv(w11, w19, w21);
  __ Udiv(x12, x19, x21);
  __ Sdiv(x13, x19, x21);
  __ Udiv(x14, x20, x21);
  __ Sdiv(x15, x20, x21);

  __ Udiv(w22, w19, w17);
  __ Sdiv(w23, w19, w17);
  __ Udiv(x24, x20, x30);
  __ Sdiv(x25, x20, x30);

  __ Udiv(x26, x16, x21);
  __ Sdiv(x27, x16, x21);
  __ Udiv(x28, x30, x21);
  __ Sdiv(x29, x30, x21);

  __ Mov(x17, 0);
  __ Udiv(w30, w16, w17);
  __ Sdiv(w19, w16, w17);
  __ Udiv(x20, x16, x17);
  __ Sdiv(x21, x16, x17);
  END();

  RUN();

  CHECK_EQUAL_64(1, x0);
  CHECK_EQUAL_64(0xFFFFFFFF, x1);
  CHECK_EQUAL_64(1, x2);
  CHECK_EQUAL_64(0xFFFFFFFF, x3);
  CHECK_EQUAL_64(1, x4);
  CHECK_EQUAL_64(1, x5);
  CHECK_EQUAL_64(0, x6);
  CHECK_EQUAL_64(1, x7);
  CHECK_EQUAL_64(0, x8);
  CHECK_EQUAL_64(0xFFFFFFFF00000001UL, x9);
  CHECK_EQUAL_64(0x40000000, x10);
  CHECK_EQUAL_64(0xC0000000, x11);
  CHECK_EQUAL_64(0x40000000, x12);
  CHECK_EQUAL_64(0x40000000, x13);
  CHECK_EQUAL_64(0x4000000000000000UL, x14);
  CHECK_EQUAL_64(0xC000000000000000UL, x15);
  CHECK_EQUAL_64(0, x22);
  CHECK_EQUAL_64(0x80000000, x23);
  CHECK_EQUAL_64(0, x24);
  CHECK_EQUAL_64(0x8000000000000000UL, x25);
  CHECK_EQUAL_64(0, x26);
  CHECK_EQUAL_64(0, x27);
  CHECK_EQUAL_64(0x7FFFFFFFFFFFFFFFUL, x28);
  CHECK_EQUAL_64(0, x29);
  CHECK_EQUAL_64(0, x30);
  CHECK_EQUAL_64(0, x19);
  CHECK_EQUAL_64(0, x20);
  CHECK_EQUAL_64(0, x21);
}

TEST(rbit_rev) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x24, 0xFEDCBA9876543210UL);
  __ Rbit(w0, w24);
  __ Rbit(x1, x24);
  __ Rev16(w2, w24);
  __ Rev16(x3, x24);
  __ Rev(w4, w24);
  __ Rev32(x5, x24);
  __ Rev(x6, x24);
  END();

  RUN();

  CHECK_EQUAL_64(0x084C2A6E, x0);
  CHECK_EQUAL_64(0x084C2A6E195D3B7FUL, x1);
  CHECK_EQUAL_64(0x54761032, x2);
  CHECK_EQUAL_64(0xDCFE98BA54761032UL, x3);
  CHECK_EQUAL_64(0x10325476, x4);
  CHECK_EQUAL_64(0x98BADCFE10325476UL, x5);
  CHECK_EQUAL_64(0x1032547698BADCFEUL, x6);
}

TEST(clz_cls) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x24, 0x0008000000800000UL);
  __ Mov(x25, 0xFF800000FFF80000UL);
  __ Mov(x26, 0);
  __ Clz(w0, w24);
  __ Clz(x1, x24);
  __ Clz(w2, w25);
  __ Clz(x3, x25);
  __ Clz(w4, w26);
  __ Clz(x5, x26);
  __ Cls(w6, w24);
  __ Cls(x7, x24);
  __ Cls(w8, w25);
  __ Cls(x9, x25);
  __ Cls(w10, w26);
  __ Cls(x11, x26);
  END();

  RUN();

  CHECK_EQUAL_64(8, x0);
  CHECK_EQUAL_64(12, x1);
  CHECK_EQUAL_64(0, x2);
  CHECK_EQUAL_64(0, x3);
  CHECK_EQUAL_64(32, x4);
  CHECK_EQUAL_64(64, x5);
  CHECK_EQUAL_64(7, x6);
  CHECK_EQUAL_64(11, x7);
  CHECK_EQUAL_64(12, x8);
  CHECK_EQUAL_64(8, x9);
  CHECK_EQUAL_64(31, x10);
  CHECK_EQUAL_64(63, x11);
}

TEST(label) {
  INIT_V8();
  SETUP();

  Label label_1, label_2, label_3, label_4;

  START();
  __ Mov(x0, 0x1);
  __ Mov(x1, 0x0);
  __ Mov(x22, lr);    // Save lr.

  __ B(&label_1);
  __ B(&label_1);
  __ B(&label_1);     // Multiple branches to the same label.
  __ Mov(x0, 0x0);
  __ Bind(&label_2);
  __ B(&label_3);     // Forward branch.
  __ Mov(x0, 0x0);
  __ Bind(&label_1);
  __ B(&label_2);     // Backward branch.
  __ Mov(x0, 0x0);
  __ Bind(&label_3);
  __ Bl(&label_4);
  END();

  __ Bind(&label_4);
  __ Mov(x1, 0x1);
  __ Mov(lr, x22);
  END();

  RUN();

  CHECK_EQUAL_64(0x1, x0);
  CHECK_EQUAL_64(0x1, x1);
}

TEST(branch_at_start) {
  INIT_V8();
  SETUP();

  Label good, exit;

  // Test that branches can exist at the start of the buffer. (This is a
  // boundary condition in the label-handling code.) To achieve this, we have
  // to work around the code generated by START.
  RESET();
  __ B(&good);

  START_AFTER_RESET();
  __ Mov(x0, 0x0);
  END();

  __ Bind(&exit);
  START_AFTER_RESET();
  __ Mov(x0, 0x1);
  END();

  __ Bind(&good);
  __ B(&exit);
  END();

  RUN();

  CHECK_EQUAL_64(0x1, x0);
}

TEST(adr) {
  INIT_V8();
  SETUP();

  Label label_1, label_2, label_3, label_4;

  START();
  __ Mov(x0, 0x0);        // Set to non-zero to indicate failure.
  __ Adr(x1, &label_3);   // Set to zero to indicate success.

  __ Adr(x2, &label_1);   // Multiple forward references to the same label.
  __ Adr(x3, &label_1);
  __ Adr(x4, &label_1);

  __ Bind(&label_2, BranchTargetIdentifier::kBtiJump);
  __ Eor(x5, x2, Operand(x3));  // Ensure that x2,x3 and x4 are identical.
  __ Eor(x6, x2, Operand(x4));
  __ Orr(x0, x0, Operand(x5));
  __ Orr(x0, x0, Operand(x6));
  __ Br(x2);  // label_1, label_3

  __ Bind(&label_3, BranchTargetIdentifier::kBtiJump);
  __ Adr(x2, &label_3);   // Self-reference (offset 0).
  __ Eor(x1, x1, Operand(x2));
  __ Adr(x2, &label_4);   // Simple forward reference.
  __ Br(x2);  // label_4

  __ Bind(&label_1, BranchTargetIdentifier::kBtiJump);
  __ Adr(x2, &label_3);   // Multiple reverse references to the same label.
  __ Adr(x3, &label_3);
  __ Adr(x4, &label_3);
  __ Adr(x5, &label_2);   // Simple reverse reference.
  __ Br(x5);  // label_2

  __ Bind(&label_4, BranchTargetIdentifier::kBtiJump);
  END();

  RUN();

  CHECK_EQUAL_64(0x0, x0);
  CHECK_EQUAL_64(0x0, x1);
}

TEST(adr_far) {
  INIT_V8();

  int max_range = 1 << (Instruction::ImmPCRelRangeBitwidth - 1);
  SETUP_SIZE(max_range + 1000 * kInstrSize);

  Label done, fail;
  Label test_near, near_forward, near_backward;
  Label test_far, far_forward, far_backward;

  START();
  __ Mov(x0, 0x0);

  __ Bind(&test_near);
  __ Adr(x10, &near_forward, MacroAssembler::kAdrFar);
  __ Br(x10);
  __ B(&fail);
  __ Bind(&near_backward, BranchTargetIdentifier::kBtiJump);
  __ Orr(x0, x0, 1 << 1);
  __ B(&test_far);

  __ Bind(&near_forward, BranchTargetIdentifier::kBtiJump);
  __ Orr(x0, x0, 1 << 0);
  __ Adr(x10, &near_backward, MacroAssembler::kAdrFar);
  __ Br(x10);

  __ Bind(&test_far);
  __ Adr(x10, &far_forward, MacroAssembler::kAdrFar);
  __ Br(x10);
  __ B(&fail);
  __ Bind(&far_backward, BranchTargetIdentifier::kBtiJump);
  __ Orr(x0, x0, 1 << 3);
  __ B(&done);

  for (int i = 0; i < max_range / kInstrSize + 1; ++i) {
    if (i % 100 == 0) {
      // If we do land in this code, we do not want to execute so many nops
      // before reaching the end of test (especially if tracing is activated).
      __ b(&fail);
    } else {
      __ nop();
    }
  }

  __ Bind(&far_forward, BranchTargetIdentifier::kBtiJump);
  __ Orr(x0, x0, 1 << 2);
  __ Adr(x10, &far_backward, MacroAssembler::kAdrFar);
  __ Br(x10);

  __ B(&done);
  __ Bind(&fail);
  __ Orr(x0, x0, 1 << 4);
  __ Bind(&done);

  END();

  RUN();

  CHECK_EQUAL_64(0xF, x0);
}

TEST(branch_cond) {
  INIT_V8();
  SETUP();

  Label wrong;

  START();
  __ Mov(x0, 0x1);
  __ Mov(x1, 0x1);
  __ Mov(x2, 0x8000000000000000L);

  // For each 'cmp' instruction below, condition codes other than the ones
  // following it would branch.

  __ Cmp(x1, 0);
  __ B(&wrong, eq);
  __ B(&wrong, lo);
  __ B(&wrong, mi);
  __ B(&wrong, vs);
  __ B(&wrong, ls);
  __ B(&wrong, lt);
  __ B(&wrong, le);
  Label ok_1;
  __ B(&ok_1, ne);
  __ Mov(x0, 0x0);
  __ Bind(&ok_1);

  __ Cmp(x1, 1);
  __ B(&wrong, ne);
  __ B(&wrong, lo);
  __ B(&wrong, mi);
  __ B(&wrong, vs);
  __ B(&wrong, hi);
  __ B(&wrong, lt);
  __ B(&wrong, gt);
  Label ok_2;
  __ B(&ok_2, pl);
  __ Mov(x0, 0x0);
  __ Bind(&ok_2);

  __ Cmp(x1, 2);
  __ B(&wrong, eq);
  __ B(&wrong, hs);
  __ B(&wrong, pl);
  __ B(&wrong, vs);
  __ B(&wrong, hi);
  __ B(&wrong, ge);
  __ B(&wrong, gt);
  Label ok_3;
  __ B(&ok_3, vc);
  __ Mov(x0, 0x0);
  __ Bind(&ok_3);

  __ Cmp(x2, 1);
  __ B(&wrong, eq);
  __ B(&wrong, lo);
  __ B(&wrong, mi);
  __ B(&wrong, vc);
  __ B(&wrong, ls);
  __ B(&wrong, ge);
  __ B(&wrong, gt);
  Label ok_4;
  __ B(&ok_4, le);
  __ Mov(x0, 0x0);
  __ Bind(&ok_4);

  Label ok_5;
  __ b(&ok_5, al);
  __ Mov(x0, 0x0);
  __ Bind(&ok_5);

  Label ok_6;
  __ b(&ok_6, nv);
  __ Mov(x0, 0x0);
  __ Bind(&ok_6);

  END();

  __ Bind(&wrong);
  __ Mov(x0, 0x0);
  END();

  RUN();

  CHECK_EQUAL_64(0x1, x0);
}

TEST(branch_to_reg) {
  INIT_V8();
  SETUP();

  // Test br.
  Label fn1, after_fn1, after_bl1;

  START();
  __ Mov(x29, lr);

  __ Mov(x1, 0);
  __ B(&after_fn1);

  __ Bind(&fn1);
  __ Mov(x0, lr);
  __ Mov(x1, 42);
  __ Br(x0);

  __ Bind(&after_fn1);
  __ Bl(&fn1);
  __ Bind(&after_bl1, BranchTargetIdentifier::kBtiJump);  // For Br(x0) in fn1.

  // Test blr.
  Label fn2, after_fn2, after_bl2;

  __ Mov(x2, 0);
  __ B(&after_fn2);

  __ Bind(&fn2);
  __ Mov(x0, lr);
  __ Mov(x2, 84);
  __ Blr(x0);

  __ Bind(&after_fn2);
  __ Bl(&fn2);
  __ Bind(&after_bl2, BranchTargetIdentifier::kBtiCall);  // For Blr(x0) in fn2.
  __ Mov(x3, lr);

  __ Mov(lr, x29);
  END();

  RUN();

  CHECK_EQUAL_64(core.xreg(3) + kInstrSize, x0);
  CHECK_EQUAL_64(42, x1);
  CHECK_EQUAL_64(84, x2);
}

static void BtiHelper(Register ipreg) {
  SETUP();

  Label jump_target, jump_call_target, call_target, test_pacibsp,
      pacibsp_target, done;
  START();
  UseScratchRegisterScope temps(&masm);
  temps.Exclude(ipreg);

  __ Adr(x0, &jump_target);
  __ Br(x0);
  __ Nop();

  __ Bind(&jump_target, BranchTargetIdentifier::kBtiJump);
  __ Adr(x0, &call_target);
  __ Blr(x0);

  __ Adr(ipreg, &jump_call_target);
  __ Blr(ipreg);
  __ Adr(lr, &test_pacibsp);  // Make Ret return to test_pacibsp.
  __ Br(ipreg);

  __ Bind(&test_pacibsp, BranchTargetIdentifier::kNone);
  __ Adr(ipreg, &pacibsp_target);
  __ Blr(ipreg);
  __ Adr(lr, &done);  // Make Ret return to done label.
  __ Br(ipreg);

  __ Bind(&call_target, BranchTargetIdentifier::kBtiCall);
  __ Ret();

  __ Bind(&jump_call_target, BranchTargetIdentifier::kBtiJumpCall);
  __ Ret();

  __ Bind(&pacibsp_target, BranchTargetIdentifier::kPacibsp);
  __ Autibsp();
  __ Ret();

  __ Bind(&done);
  END();

#ifdef USE_SIMULATOR
  simulator.SetGuardedPages(true);
  RUN();
#endif  // USE_SIMULATOR
}

TEST(bti) {
  BtiHelper(x16);
  BtiHelper(x17);
}

TEST(unguarded_bti_is_nop) {
  SETUP();

  Label start, none, c, j, jc;
  START();
  __ B(&start);
  __ Bind(&none, BranchTargetIdentifier::kBti);
  __ Bind(&c, BranchTargetIdentifier::kBtiCall);
  __ Bind(&j, BranchTargetIdentifier::kBtiJump);
  __ Bind(&jc, BranchTargetIdentifier::kBtiJumpCall);
  CHECK(__ SizeOfCodeGeneratedSince(&none) == 4 * kInstrSize);
  __ Ret();

  Label jump_to_c, call_to_j;
  __ Bind(&start);
  __ Adr(x0, &none);
  __ Adr(lr, &jump_to_c);
  __ Br(x0);

  __ Bind(&jump_to_c);
  __ Adr(x0, &c);
  __ Adr(lr, &call_to_j);
  __ Br(x0);

  __ Bind(&call_to_j);
  __ Adr(x0, &j);
  __ Blr(x0);
  END();

#ifdef USE_SIMULATOR
  simulator.SetGuardedPages(false);
  RUN();
#endif  // USE_SIMULATOR
}

TEST(compare_branch) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x0, 0);
  __ Mov(x1, 0);
  __ Mov(x2, 0);
  __ Mov(x3, 0);
  __ Mov(x4, 0);
  __ Mov(x5, 0);
  __ Mov(x16, 0);
  __ Mov(x17, 42);

  Label zt, zt_end;
  __ Cbz(w16, &zt);
  __ B(&zt_end);
  __ Bind(&zt);
  __ Mov(x0, 1);
  __ Bind(&zt_end);

  Label zf, zf_end;
  __ Cbz(x17, &zf);
  __ B(&zf_end);
  __ Bind(&zf);
  __ Mov(x1, 1);
  __ Bind(&zf_end);

  Label nzt, nzt_end;
  __ Cbnz(w17, &nzt);
  __ B(&nzt_end);
  __ Bind(&nzt);
  __ Mov(x2, 1);
  __ Bind(&nzt_end);

  Label nzf, nzf_end;
  __ Cbnz(x16, &nzf);
  __ B(&nzf_end);
  __ Bind(&nzf);
  __ Mov(x3, 1);
  __ Bind(&nzf_end);

  __ Mov(x19, 0xFFFFFFFF00000000UL);

  Label a, a_end;
  __ Cbz(w19, &a);
  __ B(&a_end);
  __ Bind(&a);
  __ Mov(x4, 1);
  __ Bind(&a_end);

  Label b, b_end;
  __ Cbnz(w19, &b);
  __ B(&b_end);
  __ Bind(&b);
  __ Mov(x5, 1);
  __ Bind(&b_end);

  END();

  RUN();

  CHECK_EQUAL_64(1, x0);
  CHECK_EQUAL_64(0, x1);
  CHECK_EQUAL_64(1, x2);
  CHECK_EQUAL_64(0, x3);
  CHECK_EQUAL_64(1, x4);
  CHECK_EQUAL_64(0, x5);
}

TEST(test_branch) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x0, 0);
  __ Mov(x1, 0);
  __ Mov(x2, 0);
  __ Mov(x3, 0);
  __ Mov(x16, 0xAAAAAAAAAAAAAAAAUL);

  Label bz, bz_end;
  __ Tbz(w16, 0, &bz);
  __ B(&bz_end);
  __ Bind(&bz);
  __ Mov(x0, 1);
  __ Bind(&bz_end);

  Label bo, bo_end;
  __ Tbz(x16, 63, &bo);
  __ B(&bo_end);
  __ Bind(&bo);
  __ Mov(x1, 1);
  __ Bind(&bo_end);

  Label nbz, nbz_end;
  __ Tbnz(x16, 61, &nbz);
  __ B(&nbz_end);
  __ Bind(&nbz);
  __ Mov(x2, 1);
  __ Bind(&nbz_end);

  Label nbo, nbo_end;
  __ Tbnz(w16, 2, &nbo);
  __ B(&nbo_end);
  __ Bind(&nbo);
  __ Mov(x3, 1);
  __ Bind(&nbo_end);
  END();

  RUN();

  CHECK_EQUAL_64(1, x0);
  CHECK_EQUAL_64(0, x1);
  CHECK_EQUAL_64(1, x2);
  CHECK_EQUAL_64(0, x3);
}

namespace {
// Generate a block of code that, when hit, always jumps to `landing_pad`.
void GenerateLandingNops(MacroAssembler* masm, int n, Label* landing_pad) {
  for (int i = 0; i < (n - 1); i++) {
    if (i % 100 == 0) {
      masm->B(landing_pad);
    } else {
      masm->Nop();
    }
  }
  masm->B(landing_pad);
}
}  // namespace

TEST(far_branch_backward) {
  INIT_V8();

  ImmBranchType branch_types[] = {TestBranchType, CompareBranchType,
                                  CondBranchType};

  for (ImmBranchType type : branch_types) {
    int range = Instruction::ImmBranchRange(type);

    SETUP_SIZE(range + 1000 * kInstrSize);

    START();

    Label done, fail;
    // Avoid using near and far as variable name because both are defined as
    // macro in minwindef.h from Windows SDK.
    Label near_label, far_label, in_range, out_of_range;

    __ Mov(x0, 0);
    __ Mov(x1, 1);
    __ Mov(x10, 0);

    __ B(&near_label);
    __ Bind(&in_range);
    __ Orr(x0, x0, 1 << 0);

    __ B(&far_label);
    __ Bind(&out_of_range);
    __ Orr(x0, x0, 1 << 1);

    __ B(&done);

    // We use a slack and an approximate budget instead of checking precisely
    // when the branch limit is hit, since veneers and literal pool can mess
    // with our calculation of where the limit is.
    // In this test, we want to make sure we support backwards branches and the
    // range is more-or-less correct. It's not a big deal if the macro-assembler
    // got the range a little wrong, as long as it's not far off which could
    // affect performance.

    int budget =
        (range - static_cast<int>(__ SizeOfCodeGeneratedSince(&in_range))) /
        kInstrSize;

    const int kSlack = 100;

    // Generate enough code so that the next branch will be in range but we are
    // close to the limit.
    GenerateLandingNops(&masm, budget - kSlack, &fail);

    __ Bind(&near_label);
    switch (type) {
      case TestBranchType:
        __ Tbz(x10, 3, &in_range);
        // This should be:
        //     TBZ <in_range>
        CHECK_EQ(1 * kInstrSize, __ SizeOfCodeGeneratedSince(&near_label));
        break;
      case CompareBranchType:
        __ Cbz(x10, &in_range);
        // This should be:
        //     CBZ <in_range>
        CHECK_EQ(1 * kInstrSize, __ SizeOfCodeGeneratedSince(&near_label));
        break;
      case CondBranchType:
        __ Cmp(x10, 0);
        __ B(eq, &in_range);
        // This should be:
        //     CMP
        //     B.EQ <in_range>
        CHECK_EQ(2 * kInstrSize, __ SizeOfCodeGeneratedSince(&near_label));
        break;
      default:
        UNREACHABLE();
    }

    // Now go past the limit so that branches are now out of range.
    GenerateLandingNops(&masm, kSlack * 2, &fail);

    __ Bind(&far_label);
    switch (type) {
      case TestBranchType:
        __ Tbz(x10, 5, &out_of_range);
        // This should be:
        //     TBNZ <skip>
        //     B <out_of_range>
        //   skip:
        CHECK_EQ(2 * kInstrSize, __ SizeOfCodeGeneratedSince(&far_label));
        break;
      case CompareBranchType:
        __ Cbz(x10, &out_of_range);
        // This should be:
        //     CBNZ <skip>
        //     B <out_of_range>
        //   skip:
        CHECK_EQ(2 * kInstrSize, __ SizeOfCodeGeneratedSince(&far_label));
        break;
      case CondBranchType:
        __ Cmp(x10, 0);
        __ B(eq, &out_of_range);
        // This should be:
        //     CMP
        //     B.NE <skip>
        //     B <out_of_range>
        //  skip:
        CHECK_EQ(3 * kInstrSize, __ SizeOfCodeGeneratedSince(&far_label));
        break;
      default:
        UNREACHABLE();
    }

    __ Bind(&fail);
    __ Mov(x1, 0);
    __ Bind(&done);

    END();

    RUN();

    CHECK_EQUAL_64(0x3, x0);
    CHECK_EQUAL_64(1, x1);
  }
}

TEST(far_branch_simple_veneer) {
  INIT_V8();

  // Test that the MacroAssembler correctly emits veneers for forward branches
  // to labels that are outside the immediate range of branch instructions.
  int max_range =
    std::max(Instruction::ImmBranchRange(TestBranchType),
             std::max(Instruction::ImmBranchRange(CompareBranchType),
                      Instruction::ImmBranchRange(CondBranchType)));

  SETUP_SIZE(max_range + 1000 * kInstrSize);

  START();

  Label done, fail;
  Label test_tbz, test_cbz, test_bcond;
  Label success_tbz, success_cbz, success_bcond;

  __ Mov(x0, 0);
  __ Mov(x1, 1);
  __ Mov(x10, 0);

  __ Bind(&test_tbz);
  __ Tbz(x10, 7, &success_tbz);
  __ Bind(&test_cbz);
  __ Cbz(x10, &success_cbz);
  __ Bind(&test_bcond);
  __ Cmp(x10, 0);
  __ B(eq, &success_bcond);

  // Generate enough code to overflow the immediate range of the three types of
  // branches below.
  for (int i = 0; i < max_range / kInstrSize + 1; ++i) {
    if (i % 100 == 0) {
      // If we do land in this code, we do not want to execute so many nops
      // before reaching the end of test (especially if tracing is activated).
      // Also, the branches give the MacroAssembler the opportunity to emit the
      // veneers.
      __ B(&fail);
    } else {
      __ Nop();
    }
  }
  __ B(&fail);

  __ Bind(&success_tbz);
  __ Orr(x0, x0, 1 << 0);
  __ B(&test_cbz);
  __ Bind(&success_cbz);
  __ Orr(x0, x0, 1 << 1);
  __ B(&test_bcond);
  __ Bind(&success_bcond);
  __ Orr(x0, x0, 1 << 2);

  __ B(&done);
  __ Bind(&fail);
  __ Mov(x1, 0);
  __ Bind(&done);

  END();

  RUN();

  CHECK_EQUAL_64(0x7, x0);
  CHECK_EQUAL_64(0x1, x1);
}

TEST(far_branch_veneer_link_chain) {
  INIT_V8();

  // Test that the MacroAssembler correctly emits veneers for forward branches
  // that target out-of-range labels and are part of multiple instructions
  // jumping to that label.
  //
  // We test the three situations with the different types of instruction:
  // (1)- When the branch is at the start of the chain with tbz.
  // (2)- When the branch is in the middle of the chain with cbz.
  // (3)- When the branch is at the end of the chain with bcond.
  int max_range =
    std::max(Instruction::ImmBranchRange(TestBranchType),
             std::max(Instruction::ImmBranchRange(CompareBranchType),
                      Instruction::ImmBranchRange(CondBranchType)));

  SETUP_SIZE(max_range + 1000 * kInstrSize);

  START();

  Label skip, fail, done;
  Label test_tbz, test_cbz, test_bcond;
  Label success_tbz, success_cbz, success_bcond;

  __ Mov(x0, 0);
  __ Mov(x1, 1);
  __ Mov(x10, 0);

  __ B(&skip);
  // Branches at the start of the chain for situations (2) and (3).
  __ B(&success_cbz);
  __ B(&success_bcond);
  __ Nop();
  __ B(&success_bcond);
  __ B(&success_cbz);
  __ Bind(&skip);

  __ Bind(&test_tbz);
  __ Tbz(x10, 7, &success_tbz);
  __ Bind(&test_cbz);
  __ Cbz(x10, &success_cbz);
  __ Bind(&test_bcond);
  __ Cmp(x10, 0);
  __ B(eq, &success_bcond);

  skip.Unuse();
  __ B(&skip);
  // Branches at the end of the chain for situations (1) and (2).
  __ B(&success_cbz);
  __ B(&success_tbz);
  __ Nop();
  __ B(&success_tbz);
  __ B(&success_cbz);
  __ Bind(&skip);

  // Generate enough code to overflow the immediate range of the three types of
  // branches below.
  GenerateLandingNops(&masm, (max_range / kInstrSize) + 1, &fail);

  __ Bind(&success_tbz);
  __ Orr(x0, x0, 1 << 0);
  __ B(&test_cbz);
  __ Bind(&success_cbz);
  __ Orr(x0, x0, 1 << 1);
  __ B(&test_bcond);
  __ Bind(&success_bcond);
  __ Orr(x0, x0, 1 << 2);

  __ B(&done);
  __ Bind(&fail);
  __ Mov(x1, 0);
  __ Bind(&done);

  END();

  RUN();

  CHECK_EQUAL_64(0x7, x0);
  CHECK_EQUAL_64(0x1, x1);
}

TEST(far_branch_veneer_broken_link_chain) {
  INIT_V8();

  // Check that the MacroAssembler correctly handles the situation when removing
  // a branch from the link chain of a label and the two links on each side of
  // the removed branch cannot be linked together (out of range).
  //
  // We want to generate the following code, we test with tbz because it has a
  // small range:
  //
  // ~~~
  // 1: B <far>
  //          :
  //          :
  //          :
  // 2: TBZ <far> -------.
  //          :          |
  //          :          | out of range
  //          :          |
  // 3: TBZ <far>        |
  //          |          |
  //          | in range |
  //          V          |
  // far:              <-'
  // ~~~
  //
  // If we say that the range of TBZ is 3 lines on this graph, then we can get
  // into a situation where the link chain gets broken. When emitting the two
  // TBZ instructions, we are in range of the previous branch in the chain so
  // we'll generate a TBZ and not a TBNZ+B sequence that can encode a bigger
  // range.
  //
  // However, the first TBZ (2), is out of range of the far label so a veneer
  // will be generated after the second TBZ (3). And this will result in a
  // broken chain because we can no longer link from (3) back to (1).
  //
  // ~~~
  // 1: B <far>     <-.
  //                  :
  //                  : out of range
  //                  :
  // 2: TBZ <veneer>  :
  //                  :
  //                  :
  //                  :
  // 3: TBZ <far> ----'
  //
  //    B <skip>
  // veneer:
  //    B <far>
  // skip:
  //
  // far:
  // ~~~
  //
  // This test makes sure the MacroAssembler is able to resolve this case by,
  // for instance, resolving (1) early and making it jump to <veneer> instead of
  // <far>.

  int max_range = Instruction::ImmBranchRange(TestBranchType);
  int inter_range = max_range / 2 + max_range / 10;

  SETUP_SIZE(3 * inter_range + 1000 * kInstrSize);

  START();

  Label fail, done;
  Label test_1, test_2, test_3;
  Label far_target;

  __ Mov(x0, 0);  // Indicates the origin of the branch.
  __ Mov(x1, 1);
  __ Mov(x10, 0);

  // First instruction in the label chain.
  __ Bind(&test_1);
  __ Mov(x0, 1);
  __ B(&far_target);

  GenerateLandingNops(&masm, inter_range / kInstrSize, &fail);

  // Will need a veneer to point to reach the target.
  __ Bind(&test_2);
  __ Mov(x0, 2);
  {
    Label tbz;
    __ Bind(&tbz);
    __ Tbz(x10, 7, &far_target);
    // This should be a single TBZ since the previous link is in range at this
    // point.
    CHECK_EQ(1 * kInstrSize, __ SizeOfCodeGeneratedSince(&tbz));
  }

  GenerateLandingNops(&masm, inter_range / kInstrSize, &fail);

  // Does not need a veneer to reach the target, but the initial branch
  // instruction is out of range.
  __ Bind(&test_3);
  __ Mov(x0, 3);
  {
    Label tbz;
    __ Bind(&tbz);
    __ Tbz(x10, 7, &far_target);
    // This should be a single TBZ since the previous link is in range at this
    // point.
    CHECK_EQ(1 * kInstrSize, __ SizeOfCodeGeneratedSince(&tbz));
  }

  // A veneer will be generated for the first TBZ, which will then remove the
  // label from the chain and break it because the second TBZ is out of range of
  // the first branch.
  // The MacroAssembler should be able to cope with this.

  GenerateLandingNops(&masm, inter_range / kInstrSize, &fail);

  __ B(&fail);

  __ Bind(&far_target);
  __ Cmp(x0, 1);
  __ B(eq, &test_2);
  __ Cmp(x0, 2);
  __ B(eq, &test_3);

  __ B(&done);
  __ Bind(&fail);
  __ Mov(x1, 0);
  __ Bind(&done);

  END();

  RUN();

  CHECK_EQUAL_64(0x3, x0);
  CHECK_EQUAL_64(0x1, x1);
}

TEST(branch_type) {
  INIT_V8();

  SETUP();

  Label fail, done;

  START();
  __ Mov(x0, 0x0);
  __ Mov(x10, 0x7);
  __ Mov(x11, 0x0);

  // Test non taken branches.
  __ Cmp(x10, 0x7);
  __ B(&fail, ne);
  __ B(&fail, never);
  __ B(&fail, reg_zero, x10);
  __ B(&fail, reg_not_zero, x11);
  __ B(&fail, reg_bit_clear, x10, 0);
  __ B(&fail, reg_bit_set, x10, 3);

  // Test taken branches.
  Label l1, l2, l3, l4, l5;
  __ Cmp(x10, 0x7);
  __ B(&l1, eq);
  __ B(&fail);
  __ Bind(&l1);
  __ B(&l2, always);
  __ B(&fail);
  __ Bind(&l2);
  __ B(&l3, reg_not_zero, x10);
  __ B(&fail);
  __ Bind(&l3);
  __ B(&l4, reg_bit_clear, x10, 15);
  __ B(&fail);
  __ Bind(&l4);
  __ B(&l5, reg_bit_set, x10, 1);
  __ B(&fail);
  __ Bind(&l5);

  __ B(&done);

  __ Bind(&fail);
  __ Mov(x0, 0x1);

  __ Bind(&done);

  END();

  RUN();

  CHECK_EQUAL_64(0x0,
"""


```