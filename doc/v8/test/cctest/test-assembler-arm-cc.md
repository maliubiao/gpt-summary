Response:
Let's break down the thought process for analyzing this V8 assembler test file.

**1. Initial Understanding of the File's Purpose:**

The file name `v8/test/cctest/test-assembler-arm.cc` immediately suggests it's a test file (`test`) within the `cctest` (C++ test) framework, specifically for the ARM architecture (`arm`). The "assembler" part indicates it's testing the code generation capabilities of V8's assembler for ARM. The `.cc` extension confirms it's a C++ source file.

**2. Examining the Header and Imports:**

The initial comments are standard V8 copyright and licensing information. The `#include` statements are crucial for understanding the dependencies and tools used:

* `<iostream>`: Standard C++ input/output. Likely used for debugging `printf` statements.
* `"src/base/numbers/double.h"`:  Deals with double-precision floating-point numbers. Suggests tests involving floating-point operations.
* `"src/base/utils/random-number-generator.h"`: Might be used for tests that require some randomness, though it's not immediately apparent in the provided snippet.
* `"src/codegen/assembler-inl.h"` and `"src/codegen/macro-assembler.h"`:  These are core V8 headers for the assembler. They define the classes and methods used to generate machine code.
* `"src/execution/simulator.h"`:  Indicates that the tests might be running within a simulator environment, which is common for testing architecture-specific code without needing actual hardware.
* `"src/heap/factory.h"`: Used for creating V8 objects on the heap, suggesting some interaction with V8's object model, though less direct in this assembler test.
* `"src/utils/ostreams.h"`: Likely used for outputting debugging information.
* `"test/cctest/assembler-helper-arm.h"`: Provides helper functions specific to testing the ARM assembler.
* `"test/cctest/cctest.h"`:  The main header for the `cctest` framework.
* `"test/common/value-helper.h"`: Offers utility functions for working with values in tests.

**3. Analyzing the `namespace`:**

The code is within the `v8::internal::test_assembler_arm` namespace. This confirms the file's purpose and organization within the V8 project.

**4. Inspecting the `TEST()` Macros:**

The core of the file consists of several `TEST(N)` macros. This is a standard construct within the `cctest` framework. Each `TEST()` defines an independent test case. The number `N` is simply an identifier for the test.

**5. Deconstructing Individual Test Cases (Example: `TEST(0)`):**

Let's take `TEST(0)` as an example:

* `CcTest::InitializeVM();`: Initializes the V8 virtual machine for the test.
* `Isolate* isolate = CcTest::i_isolate();`: Gets the current V8 isolate (an isolated instance of the V8 engine).
* `HandleScope scope(isolate);`:  Manages the lifetime of V8 handles (smart pointers for V8 objects).
* `Assembler assm(AssemblerOptions{});`: Creates an `Assembler` object, which is the key class for generating ARM assembly code.
* `__ add(r0, r0, Operand(r1));`:  This is the core of the test. `__` is a shorthand for `assm.`. This line generates an ARM `add` instruction, adding the contents of register `r1` to `r0` and storing the result in `r0`. `Operand(r1)` specifies the source operand.
* `__ mov(pc, Operand(lr));`: Generates a `mov` instruction to move the contents of the link register (`lr`) into the program counter (`pc`). This is the standard way to return from a function in ARM.
* `CodeDesc desc; assm.GetCode(isolate, &desc);`:  Gets the generated machine code from the `Assembler` and stores its description in `desc`.
* `Handle<Code> code = Factory::CodeBuilder(...).Build();`: Creates a V8 `Code` object (representing executable code) from the generated assembly.
* `#ifdef DEBUG ... Print(*code, os); #endif`:  Conditionally prints the generated assembly code to the standard output if the `DEBUG` flag is defined. This is for debugging purposes.
* `auto f = GeneratedCode<F_iiiii>::FromCode(isolate, *code);`:  Creates a function pointer `f` to the generated code. `F_iiiii` is likely a template specifying the calling convention (five integer arguments, integer return).
* `int res = reinterpret_cast<int>(f.Call(3, 4, 0, 0, 0));`:  Calls the generated ARM code, passing in the integers 3 and 4 as arguments. The result is stored in `res`.
* `::printf("f() = %d\n", res);`: Prints the result to the console.
* `CHECK_EQ(7, res);`:  Asserts that the result of the assembly code execution is equal to 7.

**6. Identifying Patterns and Common Themes:**

By examining several test cases, you can identify common patterns:

* **Initialization:** Each test starts by initializing the V8 VM and creating an `Assembler`.
* **Code Generation:**  They use the `Assembler` object (`assm`) and its methods (like `add`, `mov`, `ldr`, `str`, `vadd`, etc.) to generate ARM instructions.
* **Labels and Control Flow:** Tests like `TEST(1)` and `TEST(2)` demonstrate the use of `Label` objects and branching instructions (`b`, `teq`) to create loops and conditional execution.
* **Memory Access:** Several tests involve loading and storing data to and from memory using `ldr` and `str` with `MemOperand`.
* **Floating-Point Operations:** Tests involving `VFPv3` features (`TEST(4)`, `TEST(7)`, `TEST(8)`, etc.) utilize VFP instructions for floating-point arithmetic, conversions, and memory operations.
* **Bit Manipulation:**  `TEST(5)` tests ARMv7 bitfield instructions.
* **Saturating Arithmetic:** `TEST(6)` examines saturating arithmetic operations.
* **Calling Generated Code:**  The `GeneratedCode` template is used to create callable functions from the generated assembly, and these functions are then executed with specific inputs.
* **Assertions:** `CHECK_EQ` (and likely other `CHECK_*` macros) are used to verify the correctness of the generated code by comparing the actual output with the expected output.

**7. Answering the Specific Questions:**

Based on this analysis, you can now directly answer the questions posed in the prompt:

* **Functionality:** The file tests the ARM assembler in V8 by generating small snippets of ARM assembly code and verifying their behavior. It covers basic arithmetic, control flow, memory access, floating-point operations, and other ARM-specific instructions.
* **`.tq` Extension:** The filename ends with `.cc`, not `.tq`, so it's a C++ test file, not a Torque file.
* **Relationship to JavaScript:** While this C++ code directly generates machine code, it's testing the *underlying mechanisms* that V8 uses to execute JavaScript. When V8 compiles JavaScript, it often generates machine code for the target architecture. This file tests the correctness of that code generation process for ARM.
* **Code Logic and Examples:** Each `TEST()` case provides an example of a small code logic snippet. You can analyze the ARM instructions to understand the input/output. For instance, in `TEST(0)`, the input is implicitly the arguments to the `Call()` function (3 and 4), and the output is the return value (7).
* **Common Programming Errors:** This file doesn't directly demonstrate *user* programming errors in JavaScript. Instead, it tests for errors in V8's *own* code generation logic. If there were bugs in the assembler, these tests would likely fail.
* **Summary of Functionality:** As stated earlier, the file tests the correctness of V8's ARM assembler.

**8. Iterative Refinement:**

After the initial analysis, you might go back and examine specific tests in more detail if certain aspects are unclear. For example, understanding the VFP rounding mode tests (`TEST(7)`) requires looking up the definitions of `RN`, `RM`, `RZ` and how floating-point to integer conversions work in ARM. Similarly, understanding the memory layout and `offsetof` usage in tests like `TEST(3)` requires familiarity with C++ structures and memory layout.
这是v8/test/cctest/test-assembler-arm.cc的第1部分，主要功能是测试V8 JavaScript 引擎在 ARM 架构上的汇编器（Assembler）。它通过编写一系列独立的测试用例，来验证汇编器生成的 ARM 机器码的正确性。

**功能归纳:**

该文件的主要功能是为 V8 引擎的 ARM 汇编器编写单元测试。这些测试覆盖了 ARM 汇编语言的各种指令和特性，包括：

* **基本算术运算:**  加法 (`add`)，减法 (`sub`)，乘法 (`mul`) 等。
* **数据传输:**  寄存器间移动 (`mov`)，内存加载 (`ldr`)，内存存储 (`str`) 等。
* **控制流:**  跳转 (`b`)，条件跳转 (`beq`, `bne`)，标签 (`Label`) 等。
* **浮点运算 (VFP):**  加载 (`vldr`)，存储 (`vstr`)，加法 (`vadd`)，减法 (`vsub`)，乘法 (`vmul`)，除法 (`vdiv`)，绝对值 (`vabs`)，取反 (`vneg`)，类型转换 (`vcvt`) 等。
* **位域操作 (ARMv7):**  提取位域 (`ubfx`, `sbfx`)，位域清除 (`bfc`)，位域插入 (`bfi`)。
* **饱和运算:**  无符号饱和 (`usat`)。
* **VFP 舍入模式:** 测试浮点数到整数转换时的不同舍入行为。
* **VFP 多重加载/存储:**  使用 `vldm` 和 `vstm` 指令批量加载和存储浮点数。
* **使用进位标志的指令:** `adc` 指令。
* **VFP 规范化 NaN 模式:** 测试处理 NaN (非数字) 值的行为。
* **VFP 寄存器使用:**  测试使用 d16-d31 等扩展 VFP 寄存器的指令。

**如果 v8/test/cctest/test-assembler-arm.cc 以 .tq 结尾:**

如果文件名以 `.tq` 结尾，那么它将是一个 **Torque** 源代码文件。Torque 是 V8 使用的一种领域特定语言 (DSL)，用于生成高效的 C++ 代码，包括一些底层的运行时代码。  这个文件现在是 `.cc` 结尾，所以是 C++ 代码，直接使用汇编器 API。

**与 JavaScript 功能的关系及举例:**

虽然这个文件是用 C++ 编写的，并且直接操作汇编指令，但它直接关系到 V8 如何执行 JavaScript 代码。  当 V8 编译 JavaScript 代码时，它最终会生成目标架构（例如 ARM）的机器码。 `test-assembler-arm.cc` 中的测试用例验证了 V8 的汇编器能否正确地将 V8 的内部表示转换为高效且正确的 ARM 机器码。

例如，`TEST(0)` 测试了简单的加法运算。 这与 JavaScript 中的 `+` 运算符息息相关。 当 V8 编译类似 `let sum = a + b;` 的 JavaScript 代码时，它可能最终会生成类似于 `add r0, r0, Operand(r1)` 的 ARM 指令，就像 `TEST(0)` 中所测试的那样。

```javascript
// JavaScript 示例
function add(a, b) {
  return a + b;
}

let result = add(3, 4);
console.log(result); // 输出 7
```

在 V8 内部，当执行 `add(3, 4)` 时，可能会生成类似 `TEST(0)` 中测试的汇编代码。

**代码逻辑推理及假设输入输出:**

以 `TEST(1)` 为例，它实现了一个简单的循环来计算从 0 到输入值的累加和。

**假设输入:**  传递给生成的汇编函数的第一个参数 `r0` 的值为 `100`。

**代码逻辑:**

1. `mov(r1, Operand(r0))`: 将输入值 (100) 复制到寄存器 `r1`。
2. `mov(r0, Operand::Zero())`: 将寄存器 `r0` 初始化为 0 (用于存储累加和)。
3. `b(&C)`: 跳转到标签 `C`。
4. `bind(&L)`: 标签 `L`，循环体开始。
5. `add(r0, r0, Operand(r1))`: 将 `r1` 的值加到 `r0` 上 (累加)。
6. `sub(r1, r1, Operand(1))`: 将 `r1` 的值减 1。
7. `bind(&C)`: 标签 `C`，循环条件判断。
8. `teq(r1, Operand::Zero())`: 比较 `r1` 是否为 0。
9. `b(ne, &L)`: 如果 `r1` 不等于 0，则跳转回标签 `L` (继续循环)。
10. `mov(pc, Operand(lr))`: 如果 `r1` 等于 0，则返回。

**预期输出:**  当输入为 `100` 时，函数应该计算 0 + 1 + 2 + ... + 100 的和，即 `5050`。  测试用例中的 `CHECK_EQ(5050, res);` 正是验证了这一点。

**用户常见的编程错误举例:**

虽然这个文件测试的是汇编器，但其中一些测试也间接反映了与性能和底层行为相关的编程错误，这些错误可能不会直接导致 JavaScript 语法错误，但会影响性能或产生意外结果。

例如，`TEST(4)` 测试了浮点运算。用户可能因为对浮点数的精度和舍入规则不熟悉，而在 JavaScript 中遇到以下问题：

```javascript
let a = 0.1;
let b = 0.2;
let c = a + b;
console.log(c === 0.3); // 输出 false，因为浮点数精度问题

// 用户可能错误地认为 c 严格等于 0.3
if (c === 0.3) {
  // ... 不会执行
}
```

`TEST(7)` 测试了 VFP 的舍入模式，这与 JavaScript 中使用 `Math.round()`, `Math.floor()`, `Math.ceil()` 等函数进行舍入操作有关。  用户如果对这些舍入函数的具体行为不清楚，可能会得到意想不到的结果。

**第 1 部分功能归纳:**

总而言之，`v8/test/cctest/test-assembler-arm.cc` 的第 1 部分是一个针对 V8 引擎 ARM 汇编器的综合性测试套件的开始。它通过一系列独立的测试用例，覆盖了 ARM 架构中常见的指令和特性，旨在确保 V8 能够生成正确且高效的 ARM 机器码，从而保证 JavaScript 代码在 ARM 平台上能够正确执行。它不涉及 Torque 源代码，而是直接使用 C++ 和汇编器 API 进行测试。

### 提示词
```
这是目录为v8/test/cctest/test-assembler-arm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-arm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共5部分，请归纳一下它的功能
```

### 源代码
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

#include "src/base/numbers/double.h"
#include "src/base/utils/random-number-generator.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/macro-assembler.h"
#include "src/execution/simulator.h"
#include "src/heap/factory.h"
#include "src/utils/ostreams.h"
#include "test/cctest/assembler-helper-arm.h"
#include "test/cctest/cctest.h"
#include "test/common/value-helper.h"

namespace v8 {
namespace internal {
namespace test_assembler_arm {

using base::RandomNumberGenerator;

#define __ assm.

TEST(0) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  Assembler assm(AssemblerOptions{});

  __ add(r0, r0, Operand(r1));
  __ mov(pc, Operand(lr));

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  StdoutStream os;
  Print(*code, os);
#endif
  auto f = GeneratedCode<F_iiiii>::FromCode(isolate, *code);
  int res = reinterpret_cast<int>(f.Call(3, 4, 0, 0, 0));
  ::printf("f() = %d\n", res);
  CHECK_EQ(7, res);
}


TEST(1) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  Assembler assm(AssemblerOptions{});
  Label L, C;

  __ mov(r1, Operand(r0));
  __ mov(r0, Operand::Zero());
  __ b(&C);

  __ bind(&L);
  __ add(r0, r0, Operand(r1));
  __ sub(r1, r1, Operand(1));

  __ bind(&C);
  __ teq(r1, Operand::Zero());
  __ b(ne, &L);
  __ mov(pc, Operand(lr));

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  StdoutStream os;
  Print(*code, os);
#endif
  auto f = GeneratedCode<F_iiiii>::FromCode(isolate, *code);
  int res = reinterpret_cast<int>(f.Call(100, 0, 0, 0, 0));
  ::printf("f() = %d\n", res);
  CHECK_EQ(5050, res);
}


TEST(2) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  Assembler assm(AssemblerOptions{});
  Label L, C;

  __ mov(r1, Operand(r0));
  __ mov(r0, Operand(1));
  __ b(&C);

  __ bind(&L);
  __ mul(r0, r1, r0);
  __ sub(r1, r1, Operand(1));

  __ bind(&C);
  __ teq(r1, Operand::Zero());
  __ b(ne, &L);
  __ mov(pc, Operand(lr));

  // some relocated stuff here, not executed
  __ RecordComment("dead code, just testing relocations");
  __ mov(r0, Operand(isolate->factory()->true_value()));
  __ RecordComment("dead code, just testing immediate operands");
  __ mov(r0, Operand(-1));
  __ mov(r0, Operand(0xFF000000));
  __ mov(r0, Operand(0xF0F0F0F0));
  __ mov(r0, Operand(0xFFF0FFFF));

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  StdoutStream os;
  Print(*code, os);
#endif
  auto f = GeneratedCode<F_iiiii>::FromCode(isolate, *code);
  int res = reinterpret_cast<int>(f.Call(10, 0, 0, 0, 0));
  ::printf("f() = %d\n", res);
  CHECK_EQ(3628800, res);
}


TEST(3) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    int i;
    char c;
    int16_t s;
  };
  T t;

  Assembler assm(AssemblerOptions{});

  __ mov(ip, Operand(sp));
  __ stm(db_w, sp, {r4, fp, lr});
  __ sub(fp, ip, Operand(4));
  __ mov(r4, Operand(r0));
  __ ldr(r0, MemOperand(r4, offsetof(T, i)));
  __ mov(r2, Operand(r0, ASR, 1));
  __ str(r2, MemOperand(r4, offsetof(T, i)));
  __ ldrsb(r2, MemOperand(r4, offsetof(T, c)));
  __ add(r0, r2, Operand(r0));
  __ mov(r2, Operand(r2, LSL, 2));
  __ strb(r2, MemOperand(r4, offsetof(T, c)));
  __ ldrsh(r2, MemOperand(r4, offsetof(T, s)));
  __ add(r0, r2, Operand(r0));
  __ mov(r2, Operand(r2, ASR, 3));
  __ strh(r2, MemOperand(r4, offsetof(T, s)));
  __ ldm(ia_w, sp, {r4, fp, pc});

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  StdoutStream os;
  Print(*code, os);
#endif
  auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);
  t.i = 100000;
  t.c = 10;
  t.s = 1000;
  int res = reinterpret_cast<int>(f.Call(&t, 0, 0, 0, 0));
  ::printf("f() = %d\n", res);
  CHECK_EQ(101010, res);
  CHECK_EQ(100000/2, t.i);
  CHECK_EQ(10*4, t.c);
  CHECK_EQ(1000/8, t.s);
}


TEST(4) {
  // Test the VFP floating point instructions.
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
    int i;
    double j;
    double m;
    double n;
    float o;
    float p;
    float x;
    float y;
  };
  T t;

  // Create a function that accepts &t, and loads, manipulates, and stores
  // the doubles and floats.
  Assembler assm(AssemblerOptions{});

  if (CpuFeatures::IsSupported(VFPv3)) {
    CpuFeatureScope scope(&assm, VFPv3);

    __ mov(ip, Operand(sp));
    __ stm(db_w, sp, {r4, fp, lr});
    __ sub(fp, ip, Operand(4));

    __ mov(r4, Operand(r0));
    __ vldr(d6, r4, offsetof(T, a));
    __ vldr(d7, r4, offsetof(T, b));
    __ vadd(d5, d6, d7);
    __ vstr(d5, r4, offsetof(T, c));

    __ vmla(d5, d6, d7);
    __ vmls(d5, d5, d6);

    __ vmov(r2, r3, d5);
    __ vmov(d4, r2, r3);
    __ vstr(d4, r4, offsetof(T, b));

    // Load t.x and t.y, switch values, and store back to the struct.
    __ vldr(s0, r4, offsetof(T, x));
    __ vldr(s1, r4, offsetof(T, y));
    __ vmov(s2, s0);
    __ vmov(s0, s1);
    __ vmov(s1, s2);
    __ vstr(s0, r4, offsetof(T, x));
    __ vstr(s1, r4, offsetof(T, y));

    // Move a literal into a register that can be encoded in the instruction.
    __ vmov(d4, base::Double(1.0));
    __ vstr(d4, r4, offsetof(T, e));

    // Move a literal into a register that requires 64 bits to encode.
    // 0x3FF0000010000000 = 1.000000059604644775390625
    __ vmov(d4, base::Double(1.000000059604644775390625));
    __ vstr(d4, r4, offsetof(T, d));

    // Convert from floating point to integer.
    __ vmov(d4, base::Double(2.0));
    __ vcvt_s32_f64(s1, d4);
    __ vstr(s1, r4, offsetof(T, i));

    // Convert from integer to floating point.
    __ mov(lr, Operand(42));
    __ vmov(s1, lr);
    __ vcvt_f64_s32(d4, s1);
    __ vstr(d4, r4, offsetof(T, f));

    // Convert from fixed point to floating point.
    __ mov(lr, Operand(2468));
    __ vmov(s8, lr);
    __ vcvt_f64_s32(d4, 2);
    __ vstr(d4, r4, offsetof(T, j));

    // Test vabs.
    __ vldr(d1, r4, offsetof(T, g));
    __ vabs(d0, d1);
    __ vstr(d0, r4, offsetof(T, g));
    __ vldr(d2, r4, offsetof(T, h));
    __ vabs(d0, d2);
    __ vstr(d0, r4, offsetof(T, h));

    // Test vneg.
    __ vldr(d1, r4, offsetof(T, m));
    __ vneg(d0, d1);
    __ vstr(d0, r4, offsetof(T, m));
    __ vldr(d1, r4, offsetof(T, n));
    __ vneg(d0, d1);
    __ vstr(d0, r4, offsetof(T, n));

    // Test vmov for single-precision immediates.
    __ vmov(s0, Float32(0.25f));
    __ vstr(s0, r4, offsetof(T, o));
    __ vmov(s0, Float32(-16.0f));
    __ vstr(s0, r4, offsetof(T, p));

    __ ldm(ia_w, sp, {r4, fp, pc});

    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
    StdoutStream os;
    Print(*code, os);
#endif
    auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);
    t.a = 1.5;
    t.b = 2.75;
    t.c = 17.17;
    t.d = 0.0;
    t.e = 0.0;
    t.f = 0.0;
    t.g = -2718.2818;
    t.h = 31415926.5;
    t.i = 0;
    t.j = 0;
    t.m = -2718.2818;
    t.n = 123.456;
    t.x = 4.5;
    t.y = 9.0;
    f.Call(&t, 0, 0, 0, 0);
    CHECK_EQ(-16.0f, t.p);
    CHECK_EQ(0.25f, t.o);
    CHECK_EQ(-123.456, t.n);
    CHECK_EQ(2718.2818, t.m);
    CHECK_EQ(2, t.i);
    CHECK_EQ(2718.2818, t.g);
    CHECK_EQ(31415926.5, t.h);
    CHECK_EQ(617.0, t.j);
    CHECK_EQ(42.0, t.f);
    CHECK_EQ(1.0, t.e);
    CHECK_EQ(1.000000059604644775390625, t.d);
    CHECK_EQ(4.25, t.c);
    CHECK_EQ(-4.1875, t.b);
    CHECK_EQ(1.5, t.a);
    CHECK_EQ(4.5f, t.y);
    CHECK_EQ(9.0f, t.x);
  }
}


TEST(5) {
  // Test the ARMv7 bitfield instructions.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  Assembler assm(AssemblerOptions{});

  if (CpuFeatures::IsSupported(ARMv7)) {
    CpuFeatureScope scope(&assm, ARMv7);
    // On entry, r0 = 0xAAAAAAAA = 0b10..10101010.
    __ ubfx(r0, r0, 1, 12);  // 0b00..010101010101 = 0x555
    __ sbfx(r0, r0, 0, 5);   // 0b11..111111110101 = -11
    __ bfc(r0, 1, 3);        // 0b11..111111110001 = -15
    __ mov(r1, Operand(7));
    __ bfi(r0, r1, 3, 3);    // 0b11..111111111001 = -7
    __ mov(pc, Operand(lr));

    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
    StdoutStream os;
    Print(*code, os);
#endif
    auto f = GeneratedCode<F_iiiii>::FromCode(isolate, *code);
    int res = reinterpret_cast<int>(f.Call(0xAAAAAAAA, 0, 0, 0, 0));
    ::printf("f() = %d\n", res);
    CHECK_EQ(-7, res);
  }
}


TEST(6) {
  // Test saturating instructions.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  Assembler assm(AssemblerOptions{});

  __ usat(r1, 8, Operand(r0));           // Sat 0xFFFF to 0-255 = 0xFF.
  __ usat(r2, 12, Operand(r0, ASR, 9));  // Sat (0xFFFF>>9) to 0-4095 = 0x7F.
  __ usat(r3, 1, Operand(r0, LSL, 16));  // Sat (0xFFFF<<16) to 0-1 = 0x0.
  __ add(r0, r1, Operand(r2));
  __ add(r0, r0, Operand(r3));
  __ mov(pc, Operand(lr));

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  StdoutStream os;
  Print(*code, os);
#endif
  auto f = GeneratedCode<F_iiiii>::FromCode(isolate, *code);
  int res = reinterpret_cast<int>(f.Call(0xFFFF, 0, 0, 0, 0));
  ::printf("f() = %d\n", res);
  CHECK_EQ(382, res);
}


enum VCVTTypes {
  s32_f64,
  u32_f64
};

static void TestRoundingMode(VCVTTypes types,
                             VFPRoundingMode mode,
                             double value,
                             int expected,
                             bool expected_exception = false) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  Assembler assm(AssemblerOptions{});

  Label wrong_exception;

  __ vmrs(r1);
  // Set custom FPSCR.
  __ bic(r2, r1, Operand(kVFPRoundingModeMask | kVFPExceptionMask));
  __ orr(r2, r2, Operand(mode));
  __ vmsr(r2);

  // Load value, convert, and move back result to r0 if everything went well.
  __ vmov(d1, base::Double(value));
  switch (types) {
    case s32_f64:
      __ vcvt_s32_f64(s0, d1, kFPSCRRounding);
      break;

    case u32_f64:
      __ vcvt_u32_f64(s0, d1, kFPSCRRounding);
      break;

    default:
      UNREACHABLE();
  }
  // Check for vfp exceptions
  __ vmrs(r2);
  __ tst(r2, Operand(kVFPExceptionMask));
  // Check that we behaved as expected.
  __ b(&wrong_exception, expected_exception ? eq : ne);
  // There was no exception. Retrieve the result and return.
  __ vmov(r0, s0);
  __ mov(pc, Operand(lr));

  // The exception behaviour is not what we expected.
  // Load a special value and return.
  __ bind(&wrong_exception);
  __ mov(r0, Operand(11223344));
  __ mov(pc, Operand(lr));

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  StdoutStream os;
  Print(*code, os);
#endif
  auto f = GeneratedCode<F_iiiii>::FromCode(isolate, *code);
  int res = reinterpret_cast<int>(f.Call(0, 0, 0, 0, 0));
  ::printf("res = %d\n", res);
  CHECK_EQ(expected, res);
}


TEST(7) {
  CcTest::InitializeVM();
  // Test vfp rounding modes.

  // s32_f64 (double to integer).

  TestRoundingMode(s32_f64, RN,  0, 0);
  TestRoundingMode(s32_f64, RN,  0.5, 0);
  TestRoundingMode(s32_f64, RN, -0.5, 0);
  TestRoundingMode(s32_f64, RN,  1.5, 2);
  TestRoundingMode(s32_f64, RN, -1.5, -2);
  TestRoundingMode(s32_f64, RN,  123.7, 124);
  TestRoundingMode(s32_f64, RN, -123.7, -124);
  TestRoundingMode(s32_f64, RN,  123456.2,  123456);
  TestRoundingMode(s32_f64, RN, -123456.2, -123456);
  TestRoundingMode(s32_f64, RN, static_cast<double>(kMaxInt), kMaxInt);
  TestRoundingMode(s32_f64, RN, (kMaxInt + 0.49), kMaxInt);
  TestRoundingMode(s32_f64, RN, (kMaxInt + 1.0), kMaxInt, true);
  TestRoundingMode(s32_f64, RN, (kMaxInt + 0.5), kMaxInt, true);
  TestRoundingMode(s32_f64, RN, static_cast<double>(kMinInt), kMinInt);
  TestRoundingMode(s32_f64, RN, (kMinInt - 0.5), kMinInt);
  TestRoundingMode(s32_f64, RN, (kMinInt - 1.0), kMinInt, true);
  TestRoundingMode(s32_f64, RN, (kMinInt - 0.51), kMinInt, true);

  TestRoundingMode(s32_f64, RM,  0, 0);
  TestRoundingMode(s32_f64, RM,  0.5, 0);
  TestRoundingMode(s32_f64, RM, -0.5, -1);
  TestRoundingMode(s32_f64, RM,  123.7, 123);
  TestRoundingMode(s32_f64, RM, -123.7, -124);
  TestRoundingMode(s32_f64, RM,  123456.2,  123456);
  TestRoundingMode(s32_f64, RM, -123456.2, -123457);
  TestRoundingMode(s32_f64, RM, static_cast<double>(kMaxInt), kMaxInt);
  TestRoundingMode(s32_f64, RM, (kMaxInt + 0.5), kMaxInt);
  TestRoundingMode(s32_f64, RM, (kMaxInt + 1.0), kMaxInt, true);
  TestRoundingMode(s32_f64, RM, static_cast<double>(kMinInt), kMinInt);
  TestRoundingMode(s32_f64, RM, (kMinInt - 0.5), kMinInt, true);
  TestRoundingMode(s32_f64, RM, (kMinInt + 0.5), kMinInt);

  TestRoundingMode(s32_f64, RZ,  0, 0);
  TestRoundingMode(s32_f64, RZ,  0.5, 0);
  TestRoundingMode(s32_f64, RZ, -0.5, 0);
  TestRoundingMode(s32_f64, RZ,  123.7,  123);
  TestRoundingMode(s32_f64, RZ, -123.7, -123);
  TestRoundingMode(s32_f64, RZ,  123456.2,  123456);
  TestRoundingMode(s32_f64, RZ, -123456.2, -123456);
  TestRoundingMode(s32_f64, RZ, static_cast<double>(kMaxInt), kMaxInt);
  TestRoundingMode(s32_f64, RZ, (kMaxInt + 0.5), kMaxInt);
  TestRoundingMode(s32_f64, RZ, (kMaxInt + 1.0), kMaxInt, true);
  TestRoundingMode(s32_f64, RZ, static_cast<double>(kMinInt), kMinInt);
  TestRoundingMode(s32_f64, RZ, (kMinInt - 0.5), kMinInt);
  TestRoundingMode(s32_f64, RZ, (kMinInt - 1.0), kMinInt, true);


  // u32_f64 (double to integer).

  // Negative values.
  TestRoundingMode(u32_f64, RN, -0.5, 0);
  TestRoundingMode(u32_f64, RN, -123456.7, 0, true);
  TestRoundingMode(u32_f64, RN, static_cast<double>(kMinInt), 0, true);
  TestRoundingMode(u32_f64, RN, kMinInt - 1.0, 0, true);

  TestRoundingMode(u32_f64, RM, -0.5, 0, true);
  TestRoundingMode(u32_f64, RM, -123456.7, 0, true);
  TestRoundingMode(u32_f64, RM, static_cast<double>(kMinInt), 0, true);
  TestRoundingMode(u32_f64, RM, kMinInt - 1.0, 0, true);

  TestRoundingMode(u32_f64, RZ, -0.5, 0);
  TestRoundingMode(u32_f64, RZ, -123456.7, 0, true);
  TestRoundingMode(u32_f64, RZ, static_cast<double>(kMinInt), 0, true);
  TestRoundingMode(u32_f64, RZ, kMinInt - 1.0, 0, true);

  // Positive values.
  // kMaxInt is the maximum *signed* integer: 0x7FFFFFFF.
  static const uint32_t kMaxUInt = 0xFFFFFFFFu;
  TestRoundingMode(u32_f64, RZ,  0, 0);
  TestRoundingMode(u32_f64, RZ,  0.5, 0);
  TestRoundingMode(u32_f64, RZ,  123.7,  123);
  TestRoundingMode(u32_f64, RZ,  123456.2,  123456);
  TestRoundingMode(u32_f64, RZ, static_cast<double>(kMaxInt), kMaxInt);
  TestRoundingMode(u32_f64, RZ, (kMaxInt + 0.5), kMaxInt);
  TestRoundingMode(u32_f64, RZ, (kMaxInt + 1.0),
                                static_cast<uint32_t>(kMaxInt) + 1);
  TestRoundingMode(u32_f64, RZ, (kMaxUInt + 0.5), kMaxUInt);
  TestRoundingMode(u32_f64, RZ, (kMaxUInt + 1.0), kMaxUInt, true);

  TestRoundingMode(u32_f64, RM,  0, 0);
  TestRoundingMode(u32_f64, RM,  0.5, 0);
  TestRoundingMode(u32_f64, RM,  123.7, 123);
  TestRoundingMode(u32_f64, RM,  123456.2,  123456);
  TestRoundingMode(u32_f64, RM, static_cast<double>(kMaxInt), kMaxInt);
  TestRoundingMode(u32_f64, RM, (kMaxInt + 0.5), kMaxInt);
  TestRoundingMode(u32_f64, RM, (kMaxInt + 1.0),
                                static_cast<uint32_t>(kMaxInt) + 1);
  TestRoundingMode(u32_f64, RM, (kMaxUInt + 0.5), kMaxUInt);
  TestRoundingMode(u32_f64, RM, (kMaxUInt + 1.0), kMaxUInt, true);

  TestRoundingMode(u32_f64, RN,  0, 0);
  TestRoundingMode(u32_f64, RN,  0.5, 0);
  TestRoundingMode(u32_f64, RN,  1.5, 2);
  TestRoundingMode(u32_f64, RN,  123.7, 124);
  TestRoundingMode(u32_f64, RN,  123456.2,  123456);
  TestRoundingMode(u32_f64, RN, static_cast<double>(kMaxInt), kMaxInt);
  TestRoundingMode(u32_f64, RN, (kMaxInt + 0.49), kMaxInt);
  TestRoundingMode(u32_f64, RN, (kMaxInt + 0.5),
                                static_cast<uint32_t>(kMaxInt) + 1);
  TestRoundingMode(u32_f64, RN, (kMaxUInt + 0.49), kMaxUInt);
  TestRoundingMode(u32_f64, RN, (kMaxUInt + 0.5), kMaxUInt, true);
  TestRoundingMode(u32_f64, RN, (kMaxUInt + 1.0), kMaxUInt, true);
}


TEST(8) {
  // Test VFP multi load/store with ia_w.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct D {
    double a;
    double b;
    double c;
    double d;
    double e;
    double f;
    double g;
    double h;
  };
  D d;

  struct F {
    float a;
    float b;
    float c;
    float d;
    float e;
    float f;
    float g;
    float h;
  };
  F f;

  // Create a function that uses vldm/vstm to move some double and
  // single precision values around in memory.
  Assembler assm(AssemblerOptions{});

  __ mov(ip, Operand(sp));
  __ stm(db_w, sp, {r4, fp, lr});
  __ sub(fp, ip, Operand(4));

  __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(D, a))));
  __ vldm(ia_w, r4, d0, d3);
  __ vldm(ia_w, r4, d4, d7);

  __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(D, a))));
  __ vstm(ia_w, r4, d6, d7);
  __ vstm(ia_w, r4, d0, d5);

  __ add(r4, r1, Operand(static_cast<int32_t>(offsetof(F, a))));
  __ vldm(ia_w, r4, s0, s3);
  __ vldm(ia_w, r4, s4, s7);

  __ add(r4, r1, Operand(static_cast<int32_t>(offsetof(F, a))));
  __ vstm(ia_w, r4, s6, s7);
  __ vstm(ia_w, r4, s0, s5);

  __ ldm(ia_w, sp, {r4, fp, pc});

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  StdoutStream os;
  Print(*code, os);
#endif
  auto fn = GeneratedCode<F_ppiii>::FromCode(isolate, *code);
  d.a = 1.1;
  d.b = 2.2;
  d.c = 3.3;
  d.d = 4.4;
  d.e = 5.5;
  d.f = 6.6;
  d.g = 7.7;
  d.h = 8.8;

  f.a = 1.0;
  f.b = 2.0;
  f.c = 3.0;
  f.d = 4.0;
  f.e = 5.0;
  f.f = 6.0;
  f.g = 7.0;
  f.h = 8.0;

  fn.Call(&d, &f, 0, 0, 0);

  CHECK_EQ(7.7, d.a);
  CHECK_EQ(8.8, d.b);
  CHECK_EQ(1.1, d.c);
  CHECK_EQ(2.2, d.d);
  CHECK_EQ(3.3, d.e);
  CHECK_EQ(4.4, d.f);
  CHECK_EQ(5.5, d.g);
  CHECK_EQ(6.6, d.h);

  CHECK_EQ(7.0f, f.a);
  CHECK_EQ(8.0f, f.b);
  CHECK_EQ(1.0f, f.c);
  CHECK_EQ(2.0f, f.d);
  CHECK_EQ(3.0f, f.e);
  CHECK_EQ(4.0f, f.f);
  CHECK_EQ(5.0f, f.g);
  CHECK_EQ(6.0f, f.h);
}


TEST(9) {
  // Test VFP multi load/store with ia.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct D {
    double a;
    double b;
    double c;
    double d;
    double e;
    double f;
    double g;
    double h;
  };
  D d;

  struct F {
    float a;
    float b;
    float c;
    float d;
    float e;
    float f;
    float g;
    float h;
  };
  F f;

  // Create a function that uses vldm/vstm to move some double and
  // single precision values around in memory.
  Assembler assm(AssemblerOptions{});

  __ mov(ip, Operand(sp));
  __ stm(db_w, sp, {r4, fp, lr});
  __ sub(fp, ip, Operand(4));

  __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(D, a))));
  __ vldm(ia, r4, d0, d3);
  __ add(r4, r4, Operand(4 * 8));
  __ vldm(ia, r4, d4, d7);

  __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(D, a))));
  __ vstm(ia, r4, d6, d7);
  __ add(r4, r4, Operand(2 * 8));
  __ vstm(ia, r4, d0, d5);

  __ add(r4, r1, Operand(static_cast<int32_t>(offsetof(F, a))));
  __ vldm(ia, r4, s0, s3);
  __ add(r4, r4, Operand(4 * 4));
  __ vldm(ia, r4, s4, s7);

  __ add(r4, r1, Operand(static_cast<int32_t>(offsetof(F, a))));
  __ vstm(ia, r4, s6, s7);
  __ add(r4, r4, Operand(2 * 4));
  __ vstm(ia, r4, s0, s5);

  __ ldm(ia_w, sp, {r4, fp, pc});

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  StdoutStream os;
  Print(*code, os);
#endif
  auto fn = GeneratedCode<F_ppiii>::FromCode(isolate, *code);
  d.a = 1.1;
  d.b = 2.2;
  d.c = 3.3;
  d.d = 4.4;
  d.e = 5.5;
  d.f = 6.6;
  d.g = 7.7;
  d.h = 8.8;

  f.a = 1.0;
  f.b = 2.0;
  f.c = 3.0;
  f.d = 4.0;
  f.e = 5.0;
  f.f = 6.0;
  f.g = 7.0;
  f.h = 8.0;

  fn.Call(&d, &f, 0, 0, 0);

  CHECK_EQ(7.7, d.a);
  CHECK_EQ(8.8, d.b);
  CHECK_EQ(1.1, d.c);
  CHECK_EQ(2.2, d.d);
  CHECK_EQ(3.3, d.e);
  CHECK_EQ(4.4, d.f);
  CHECK_EQ(5.5, d.g);
  CHECK_EQ(6.6, d.h);

  CHECK_EQ(7.0f, f.a);
  CHECK_EQ(8.0f, f.b);
  CHECK_EQ(1.0f, f.c);
  CHECK_EQ(2.0f, f.d);
  CHECK_EQ(3.0f, f.e);
  CHECK_EQ(4.0f, f.f);
  CHECK_EQ(5.0f, f.g);
  CHECK_EQ(6.0f, f.h);
}


TEST(10) {
  // Test VFP multi load/store with db_w.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct D {
    double a;
    double b;
    double c;
    double d;
    double e;
    double f;
    double g;
    double h;
  };
  D d;

  struct F {
    float a;
    float b;
    float c;
    float d;
    float e;
    float f;
    float g;
    float h;
  };
  F f;

  // Create a function that uses vldm/vstm to move some double and
  // single precision values around in memory.
  Assembler assm(AssemblerOptions{});

  __ mov(ip, Operand(sp));
  __ stm(db_w, sp, {r4, fp, lr});
  __ sub(fp, ip, Operand(4));

  __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(D, h)) + 8));
  __ vldm(db_w, r4, d4, d7);
  __ vldm(db_w, r4, d0, d3);

  __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(D, h)) + 8));
  __ vstm(db_w, r4, d0, d5);
  __ vstm(db_w, r4, d6, d7);

  __ add(r4, r1, Operand(static_cast<int32_t>(offsetof(F, h)) + 4));
  __ vldm(db_w, r4, s4, s7);
  __ vldm(db_w, r4, s0, s3);

  __ add(r4, r1, Operand(static_cast<int32_t>(offsetof(F, h)) + 4));
  __ vstm(db_w, r4, s0, s5);
  __ vstm(db_w, r4, s6, s7);

  __ ldm(ia_w, sp, {r4, fp, pc});

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  StdoutStream os;
  Print(*code, os);
#endif
  auto fn = GeneratedCode<F_ppiii>::FromCode(isolate, *code);
  d.a = 1.1;
  d.b = 2.2;
  d.c = 3.3;
  d.d = 4.4;
  d.e = 5.5;
  d.f = 6.6;
  d.g = 7.7;
  d.h = 8.8;

  f.a = 1.0;
  f.b = 2.0;
  f.c = 3.0;
  f.d = 4.0;
  f.e = 5.0;
  f.f = 6.0;
  f.g = 7.0;
  f.h = 8.0;

  fn.Call(&d, &f, 0, 0, 0);

  CHECK_EQ(7.7, d.a);
  CHECK_EQ(8.8, d.b);
  CHECK_EQ(1.1, d.c);
  CHECK_EQ(2.2, d.d);
  CHECK_EQ(3.3, d.e);
  CHECK_EQ(4.4, d.f);
  CHECK_EQ(5.5, d.g);
  CHECK_EQ(6.6, d.h);

  CHECK_EQ(7.0f, f.a);
  CHECK_EQ(8.0f, f.b);
  CHECK_EQ(1.0f, f.c);
  CHECK_EQ(2.0f, f.d);
  CHECK_EQ(3.0f, f.e);
  CHECK_EQ(4.0f, f.f);
  CHECK_EQ(5.0f, f.g);
  CHECK_EQ(6.0f, f.h);
}


TEST(11) {
  // Test instructions using the carry flag.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct I {
    int32_t a;
    int32_t b;
    int32_t c;
    int32_t d;
  };
  I i;

  i.a = 0xABCD0001;
  i.b = 0xABCD0000;

  Assembler assm(AssemblerOptions{});

  // Test HeapObject untagging.
  __ ldr(r1, MemOperand(r0, offsetof(I, a)));
  __ mov(r1, Operand(r1, ASR, 1), SetCC);
  __ adc(r1, r1, Operand(r1), LeaveCC, cs);
  __ str(r1, MemOperand(r0, offsetof(I, a)));

  __ ldr(r2, MemOperand(r0, offsetof(I, b)));
  __ mov(r2, Operand(r2, ASR, 1), SetCC);
  __ adc(r2, r2, Operand(r2), LeaveCC, cs);
  __ str(r2, MemOperand(r0, offsetof(I, b)));

  // Test corner cases.
  __ mov(r1, Operand(0xFFFFFFFF));
  __ mov(r2, Operand::Zero());
  __ mov(r3, Operand(r1, ASR, 1), SetCC);  // Set the carry.
  __ adc(r3, r1, Operand(r2));
  __ str(r3, MemOperand(r0, offsetof(I, c)));

  __ mov(r1, Operand(0xFFFFFFFF));
  __ mov(r2, Operand::Zero());
  __ mov(r3, Operand(r2, ASR, 1), SetCC);  // Unset the carry.
  __ adc(r3, r1, Operand(r2));
  __ str(r3, MemOperand(r0, offsetof(I, d)));

  __ mov(pc, Operand(lr));

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  StdoutStream os;
  Print(*code, os);
#endif
  auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);
  f.Call(&i, 0, 0, 0, 0);

  CHECK_EQ(static_cast<int32_t>(0xABCD0001), i.a);
  CHECK_EQ(static_cast<int32_t>(0xABCD0000) >> 1, i.b);
  CHECK_EQ(0x00000000, i.c);
  CHECK_EQ(static_cast<int32_t>(0xFFFFFFFF), i.d);
}


TEST(12) {
  // Test chaining of label usages within instructions (issue 1644).
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  Assembler assm(AssemblerOptions{});
  Label target;
  __ b(eq, &target);
  __ b(ne, &target);
  __ bind(&target);
  __ nop();
}


TEST(13) {
  // Test VFP instructions using registers d16-d31.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  if (!CpuFeatures::IsSupported(VFP32DREGS)) {
    return;
  }

  struct T {
    double a;
    double b;
    double c;
    double x;
    double y;
    double z;
    double i;
    double j;
    double k;
    uint32_t low;
    uint32_t high;
  };
  T t;

  // Create a function that accepts &t, and loads, manipulates, and stores
  // the doubles and floats.
  Assembler assm(AssemblerOptions{});

  if (CpuFeatures::IsSupported(VFPv3)) {
    CpuFeatureScope scope(&assm, VFPv3);

    __ stm(db_w, sp, {r4, lr});

    // Load a, b, c into d16, d17, d18.
    __ mov(r4, Operand(r0));
    __ vldr(d16, r4, offsetof(T, a));
    __ vldr(d17, r4, offsetof(T, b));
    __ vldr(d18, r4, offsetof(T, c));

    __ vneg(d25, d16);
    __ vadd(d25, d25, d17);
    __ vsub(d25, d25, d18);
    __ vmul(d25, d25, d25);
    __ vdiv(d25, d25, d18);

    __ vmov(d16, d25);
    __ vsqrt(d17, d25);
    __ vneg(d17, d17);
    __ vabs(d17, d17);
    __ vmla(d18, d16, d17);

    // Store d16, d17, d18 into a, b, c.
    __ mov(r4, Operand(r0));
    __ vstr(d16, r4, offsetof(T, a));
    __ vstr(d17, r4, offsetof(T, b));
    __ vstr(d18, r4, offsetof(T, c));

    // Load x, y, z into d29-d31.
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, x))));
    __ vldm(ia_w, r4, d29, d31);

    // Swap d29 and d30 via r registers.
    __ vmov(r1, r2, d29);
    __ vmov(d29, d30);
    __ vmov(d30, r1, r2);

    // Convert to and from integer.
    __ vcvt_s32_f64(s1, d31);
    __ vcvt_f64_u32(d31, s1);

    // Store d29-d31 into x, y, z.
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, x))));
    __ vstm(ia_w, r4, d29, d31);

    // Move constants into d20, d21, d22 and store into i, j, k.
    __ vmov(d20, base::Double(14.7610017472335499));
    __ vmov(d21, base::Double(16.0));
    __ mov(r1, Operand(372106121));
    __ mov(r2, Operand(1079146608));
    __ vmov(NeonS32, d22, 0, r1);
    __ vmov(NeonS32, d22, 1, r2);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, i))));
    __ vstm(ia_w, r4, d20, d22);
    // Move d22 into low and high.
    __ vmov(NeonS32, r4, d22, 0);
    __ str(r4, MemOperand(r0, offsetof(T, low)));
    __ vmov(NeonS32, r4, d22, 1);
    __ str(r4, MemOperand(r0, offsetof(T, high)));

    __ ldm(ia_w, sp, {r4, pc});

    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
    StdoutStream os;
    Print(*code, os);
#endif
    auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);
    t.a = 1.5;
    t.b = 2.75;
    t.c = 17.17;
    t.x = 1.5;
    t.y = 2.75;
    t.z = 17.17;
    f.Call(&t, 0, 0, 0, 0);
    CHECK_EQ(14.7610017472335499, t.a);
    CHECK_EQ(3.84200491244266251, t.b);
    CHECK_EQ(73.8818412254460241, t.c);
    CHECK_EQ(2.75, t.x);
    CHECK_EQ(1.5, t.y);
    CHECK_EQ(17.0, t.z);
    CHECK_EQ(14.7610017472335499, t.i);
    CHECK_EQ(16.0, t.j);
    CHECK_EQ(73.8818412254460241, t.k);
    CHECK_EQ(372106121u, t.low);
    CHECK_EQ(1079146608u, t.high);
  }
}


TEST(14) {
  // Test the VFP Canonicalized Nan mode.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    double left;
    double right;
    double add_result;
    double sub_result;
    double mul_result;
    double div_result;
  };
  T t;

  // Create a function that makes the four basic operations.
  Assembler assm(AssemblerOptions{});

  // Ensure FPSCR state (as JSEntry does).
  Label fpscr_done;
  __ vmrs(r1);
  __ tst(r1, Operand(kVFPDefaultNaNModeControlBit));
  __ b(ne, &fpscr_done);
  __ orr(r1, r1, Operand(kVFPDefaultNaNModeControlBit));
  __ vmsr(r1);
  __ bind(&fpscr_done);

  __ vldr(d0, r0, offsetof(T, left));
  __ vldr(d1, r0, offsetof(T, right));
  __ vadd(d2, d0, d1);
  __ vstr(d2, r0, offsetof(T, add_result));
  __ vsub(d2, d0, d1);
  __ vstr(d2, r0, offsetof(T, sub_result));
  __ vmul(d2, d0, d1);
  __ vstr(d2, r0, offsetof(T, mul_result));
  __ vdiv(d2, d0, d1);
  __ vstr(d2, r0, offsetof(T, div_result));

  __ mov(pc, Operand(lr));

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  StdoutStream os;
  Print(*code, os);
#endif
  auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);
  t.left = base::bit_cast<double>(kHoleNanInt64);
  t.right = 1;
  t.add_result = 0;
  t.sub_result = 0;
  t.mul_result = 0;
  t.div_result = 0;
  f.Call(&t, 0, 0, 0, 0);
  const uint32_t kArmNanUpper32 = 0x7FF80000;
  const uint32_t kArmNanLower32 = 0x00000000;
#ifdef DEBUG
  const uint64_t kArmNanInt64 =
      (static_cast<uint64_t>(kArmNanUpper32) << 32) | kArmNanLower32;
  CHECK_NE(kArmNanInt64, kHoleNanInt64);
#endif
  // With VFP2 the sign of the canonicalized Nan is undefined. So
  // we remove the sign bit for the upper tests.
  CHECK_EQ(kArmNanUpper32,
           (base::bit_cast<int64_t>(t.add_result) >> 32) & 0x7FFFFFFF);
  CHECK_EQ(kArmNanLower32, base::bit_cast<int64_t>(t.add_result) & 0xFFFFFFFFu);
  CHECK_EQ(kArmNanUpper32,
           (base::bit_cast<int64_t>(t.sub_result) >> 32) & 0x7FFFFFFF);
  CHECK_EQ(kArmNanLower32, base::bit_cast<int64_t>(t.sub_result) & 0xFFFFFFFFu);
  CHECK_EQ(kArmNanUpper32,
           (base::bit_cast<int64_t>(t.mul_result) >> 32) & 0x7FFFFFFF);
  CHECK_EQ(kArmNanLower32, base::bit_cast<int64_t>(t.mul_result) & 0xFFFFFFFFu);
  CHECK_EQ(kArmNanUpper32,
           (base::bit_cast<int64_t>(t.div_result) >> 32) & 0x7FFFFFFF);
  CHECK_EQ(kArmNanLower32, base::bit_cast<int64_t>(t.div_result) & 0xFFFFFFFFu);
}

#define CHECK_EQ_SPLAT(field, ex) \
  CHECK_EQ(ex, t.field[0]);       \
  CHECK_EQ(ex, t.field[1]);       \
  CHECK_EQ(ex, t.field[2]);       \
  CHECK_EQ(ex
```