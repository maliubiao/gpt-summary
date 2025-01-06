Response:
Let's break down the thought process for analyzing this V8 Assembler test file.

**1. Initial Scan and Keywords:**

* **File Name:** `test-assembler-arm64.cc`. The `.cc` extension immediately tells us it's C++. The `arm64` part indicates it's specifically for the ARM64 architecture. `assembler` suggests it's testing assembly language generation within V8.
* **Copyright Notice:** Standard boilerplate, not crucial for understanding the file's purpose but indicates it's part of the V8 project.
* **Includes:** The `#include` directives are very informative.
    *  `<stdio.h>`, `<stdlib.h>`, `<string.h>`, `<cmath>`, `<limits>`, `<optional>`: Standard C/C++ libraries, suggesting general utility functions are used.
    *  `"src/base/utils/random-number-generator.h"`:  Indicates the possibility of tests involving randomness.
    *  `"src/codegen/arm64/assembler-arm64-inl.h"`, `"src/codegen/arm64/decoder-arm64-inl.h"`, `"src/codegen/arm64/macro-assembler-arm64-inl.h"`, `"src/codegen/arm64/utils-arm64.h"`:  These are *key*. They directly point to the core functionality being tested: generating and potentially decoding ARM64 assembly instructions. The "inl" likely means inline implementations. `macro-assembler` implies it's testing a higher-level abstraction over raw assembly.
    *  `"src/codegen/macro-assembler.h"`: A more general macro assembler interface, likely a base class or shared functionality.
    *  `"src/diagnostics/arm64/disasm-arm64.h"`:  Confirms the presence of disassembly functionality for ARM64.
    *  `"src/execution/arm64/simulator-arm64.h"`: This is a strong indicator that tests can be run in a simulated ARM64 environment.
    *  `"src/heap/factory.h"`: Hints at the potential interaction with V8's heap management.
    *  `"test/cctest/cctest.h"`, `"test/cctest/test-utils-arm64.h"`, `"test/common/assembler-tester.h"`: These are V8-specific testing frameworks and utilities.
    *  `"third_party/fp16/src/include/fp16.h"`: Implies testing of half-precision floating-point operations.

**2. Core Testing Macros:**

* **`TEST(...)`:** This is the fundamental unit of testing in this file. Each `TEST` block represents a specific test case.
* **`SETUP()` / `SETUP_SIZE()` / `SETUP_FEATURE()`:** These macros set up the testing environment. The presence of `SETUP_SIZE` suggests the allocation of a buffer for generated code. `SETUP_FEATURE` indicates the ability to test features conditionally based on CPU support.
* **`START()` / `RESET()` / `START_AFTER_RESET()`:** These manage the start of assembly code generation within a test. `RESET` is interesting; it suggests the ability to reuse the assembler buffer.
* **`END()`:**  Marks the end of the assembly code generation and includes steps to finalize the code, potentially disassemble it, and prepare it for execution.
* **`RUN()`:** Executes the generated assembly code, likely either in a simulator or on real hardware.
* **`CHECK_EQUAL_...` Macros:** These are assertion macros used to verify the results of the executed code. The variations (e.g., `CHECK_EQUAL_32`, `CHECK_EQUAL_64`, `CHECK_EQUAL_FP32`) indicate they are checking different data types and registers.

**3. Analyzing the Test Cases (Quick Sampling):**

Looking at the names of the `TEST` functions gives a good overview of what's being tested:

* `stack_ops`: Operations related to the stack pointer.
* `mvn`:  The "move negated" instruction.
* `mov`: The "move" instruction (immediate and register forms).
* `move_pair`: Moving pairs of registers.
* `mov_imm_w`, `mov_imm_x`: Moving immediate values into 32-bit and 64-bit registers.
* `orr`, `orn`, `and_`, `ands`, `bic`, `bics`, `eor`, `eon`:  Various bitwise logical operations.
* The `_extend` suffix on some tests indicates they are testing the extended register operands (e.g., `UXTB`, `SXTH`).

**4. Connecting to JavaScript (Conceptual):**

While this C++ code directly tests the *assembler*, it's crucial to understand its relationship to JavaScript. The V8 JavaScript engine compiles JavaScript code into machine code. This `test-assembler-arm64.cc` file verifies that the V8's *code generator* (which uses the assembler) can correctly produce ARM64 instructions for various JavaScript operations.

For instance, a simple JavaScript addition:

```javascript
let a = 5;
let b = 10;
let c = a + b;
```

The V8 engine would generate ARM64 assembly instructions to perform this addition. The tests in this file ensure that instructions like `ADD` are generated correctly with the right operands, flags, etc.

**5. Considering `.tq` (Torque):**

The prompt asks about `.tq` files. Torque is V8's internal language for generating code. If the file *were* `.tq`, it would mean the tests are written at a higher level of abstraction, using Torque syntax, which is then compiled down to the C++ assembler code. Since it's `.cc`, these tests are directly manipulating the C++ assembler interface.

**6. Inferring Functionality (Synthesis):**

Based on the includes, macros, and test case names, we can confidently deduce that `test-assembler-arm64.cc` is a crucial part of V8's testing infrastructure. It focuses on verifying the correctness of the ARM64 assembler, ensuring that the code generator can produce the correct machine code for various operations. This includes testing different instruction formats, immediate values, register operands, and logical operations. The simulator integration allows for controlled execution and verification of the generated code.

**Self-Correction/Refinement:**

* **Initial thought:** Maybe this file just tests individual instructions.
* **Refinement:**  While it does test individual instructions, the macros and setup suggest a more comprehensive testing framework that allows running and verifying the results of small code sequences. The inclusion of `simulator-arm64.h` is a strong indicator of this.
* **Initial thought:** The JavaScript connection is indirect.
* **Refinement:** The JavaScript connection is fundamental. While the tests are in C++, they are designed to ensure the correctness of the underlying assembly generation that enables JavaScript execution on ARM64.

By following this process of examining the code structure, key components, and test cases, we can arrive at a solid understanding of the file's purpose and its role within the V8 project.
这是 V8 JavaScript 引擎中针对 ARM64 架构的汇编器测试代码的第一部分。它的主要功能是测试 `v8/src/codegen/arm64/assembler-arm64-inl.h` 和 `v8/src/codegen/arm64/macro-assembler-arm64-inl.h` 中实现的 ARM64 汇编器的各种指令的功能和正确性。

**主要功能归纳:**

1. **测试 ARM64 汇编指令的生成和执行:**  该文件包含了大量的独立测试用例（以 `TEST(...)` 宏定义），每个测试用例都专注于测试一个或一组特定的 ARM64 汇编指令。测试会生成一段汇编代码，然后在模拟器或真实硬件上执行，并验证指令执行后的寄存器状态和标志位是否符合预期。

2. **覆盖各种指令类型:**  从提供的代码片段来看，测试涵盖了各种常见的 ARM64 指令，包括：
    * **数据传输指令:** `mov` (移动立即数和寄存器), `mvn` (移动取反), `move_pair` (移动寄存器对)。
    * **栈操作指令:**  涉及到栈指针 `sp` 的操作。
    * **逻辑运算指令:** `orr` (或), `orn` (或非), `and_` (与), `ands` (与并设置标志位), `bic` (位清除), `bics` (位清除并设置标志位), `eor` (异或), `eon` (异或非)。
    * **立即数处理:** 测试了不同范围和格式的立即数加载。
    * **扩展操作:**  测试了带有扩展操作的指令，例如 `UXTB`, `SXTH` 等。

3. **使用模拟器和硬件进行测试:**  代码中定义了 `USE_SIMULATOR` 宏，表明测试既可以在 ARM64 模拟器上运行，也可以在真实的 ARM64 硬件上运行。这确保了代码在不同环境下的正确性。

4. **提供测试基础设施:**  文件中定义了许多辅助宏（例如 `SETUP`, `START`, `END`, `RUN`, `CHECK_EQUAL_...`)，用于简化测试用例的编写和执行。这些宏负责初始化环境、生成汇编代码、运行代码、以及断言执行结果。

**关于 .tq 结尾的文件:**

如果 `v8/test/cctest/test-assembler-arm64.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码**。 Torque 是 V8 内部用于编写高效运行时代码的领域特定语言。 Torque 代码会被编译成 C++ 代码，然后再编译成机器码。

**与 JavaScript 功能的关系:**

`v8/test/cctest/test-assembler-arm64.cc` 中测试的汇编器是 V8 JavaScript 引擎的核心组件之一。当 V8 编译 JavaScript 代码时，它会将 JavaScript 代码转换成机器码，而这个转换过程会使用到这里的 ARM64 汇编器。

**举例说明:**

假设有以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
```

当 V8 执行这段代码时，它可能会生成类似以下的 ARM64 汇编指令（简化版）：

```assembly
// 加载参数 a 到寄存器 w0
mov w0, #5
// 加载参数 b 到寄存器 w1
mov w1, #10
// 执行加法运算，结果存储在 w0
add w0, w0, w1
// 将结果移动到某个用于返回值的寄存器 (假设是 w2)
mov w2, w0
// ... 返回
```

`test-assembler-arm64.cc` 中的 `TEST(mov_imm_w)` 和涉及到 `add` 指令的测试用例，就是为了验证汇编器能够正确生成和执行像上面这样的指令。

**代码逻辑推理 (假设输入与输出):**

以 `TEST(mov_x0_one)` 这个假想的测试用例为例（基于代码中的 `TEST(mov)`）：

**假设输入:** 汇编器状态为空，目标寄存器 `x0` 未定义。

**生成的汇编代码:**

```assembly
mov x0, #1
```

**预期输出:** 执行后，寄存器 `x0` 的值应该为 1。 `CHECK_EQUAL_64(1, x0)` 宏会验证这个结果。

对于更复杂的逻辑运算，例如 `TEST(orr)`：

**假设输入:** 寄存器 `x0` 的值为 `0xF0F0`，寄存器 `x1` 的值为 `0xF00000FF`。

**生成的汇编代码片段:**

```assembly
mov x0, #0xF0F0
mov x1, #0xF00000FF
orr x2, x0, x1
```

**预期输出:** 执行后，寄存器 `x2` 的值应该为 `0xF000F0FF` ( `0xF0F0` OR `0xF00000FF` )。 `CHECK_EQUAL_64(0xF000F0FF, x2)` 宏会进行验证。

**用户常见的编程错误 (与汇编器测试相关性较低):**

虽然这个测试文件主要关注汇编器的正确性，但它间接帮助避免了与代码生成相关的错误。用户在使用 JavaScript 时通常不会直接编写汇编代码，但 V8 引擎在将 JavaScript 编译成机器码的过程中，如果汇编器存在缺陷，可能会导致生成的代码出现错误，从而导致 JavaScript 程序行为异常。

**常见的用户编程错误 (JavaScript 层面，与此测试间接相关):**

* **类型错误:** 例如，尝试将一个字符串和一个数字相加，可能会导致意外的结果。V8 的代码生成器需要正确处理这些情况，而汇编器测试确保了相关的底层指令能够正确执行。
* **逻辑错误:**  例如，在 `if` 语句中使用错误的条件，可能导致程序执行错误的路径。V8 的代码生成器需要正确地将这些逻辑结构转换为条件跳转指令，而汇编器测试会覆盖这些指令的正确性。
* **内存访问错误:**  虽然这个测试文件不直接测试内存访问，但汇编器生成的加载和存储指令的正确性对于避免内存访问错误至关重要。

**总结:**

`v8/test/cctest/test-assembler-arm64.cc` 的第一部分主要功能是提供一个全面的测试套件，用于验证 V8 JavaScript 引擎中 ARM64 汇编器的各种指令的生成和执行是否正确。这对于确保 V8 在 ARM64 架构上能够可靠地执行 JavaScript 代码至关重要。 它通过大量的独立测试用例，覆盖了各种指令类型和操作数，并使用模拟器和硬件进行双重验证。虽然与用户的 JavaScript 编程错误没有直接关联，但它保证了 V8 引擎生成正确机器码的基础，从而间接地帮助避免了因代码生成错误导致的 JavaScript 程序问题。

Prompt: 
```
这是目录为v8/test/cctest/test-assembler-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共15部分，请归纳一下它的功能

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
  __ Eon(x13, x0, Operand(x1, SXTX, 3
"""


```