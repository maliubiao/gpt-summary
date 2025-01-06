Response:
The user wants to understand the functionality of the provided C++ code, which is a test file for the LoongArch64 architecture within the V8 JavaScript engine.

Here's a breakdown of the thought process to generate the response:

1. **Identify the File Type and Purpose:** The file path `v8/test/cctest/test-macro-assembler-loong64.cc` strongly suggests it's a C++ test file (`.cc`) within V8's component testing framework (`cctest`). The `loong64` part indicates it's specifically for the LoongArch64 architecture, and `macro-assembler` points to tests for the low-level code generation capabilities.

2. **Scan for Key Functionality:** Quickly skim the code, looking for `TEST(...)` macros. Each `TEST` macro represents an individual test case. List these test names. This gives a high-level overview of what the file tests.

3. **Analyze Individual Tests:** For each test case, try to understand its purpose based on the name and the code within the test.
    * `BYTESWAP`:  Clearly tests byte swapping functionality. Look for operations like `ByteSwap`.
    * `LoadConstants`:  Tests loading of constant values. Look for instructions like `li` (load immediate).
    * `jump_tables4`, `jump_tables6`:  Test the generation and execution of jump tables. Look for `GenerateSwitchTable`.
    * `ALSL_W`, `ALSL_D`: Test the `Alsl_w` and `Alsl_d` instructions (likely arithmetic shift and add).
    * `Ffint_s_uw_Ftintrz_uw_s`, etc.: These test various floating-point conversion instructions (e.g., `Ffint_s_uw`, `Ftintrz_uw_s`).
    * `OverflowInstructions`:  Tests instructions that detect arithmetic overflow (e.g., `AddOverflow_d`, `MulOverflow_w`).
    * `min_max_nan`: Tests the `Float64Min`, `Float64Max`, `Float32Min`, `Float32Max` instructions, focusing on NaN handling.
    * `Unaligned`: Likely tests handling of unaligned memory access.

4. **Infer Overall Functionality:** Based on the individual test cases, deduce the overall purpose of the file. It's a collection of tests verifying the correctness of the `MacroAssembler` for the LoongArch64 architecture, specifically testing its ability to generate correct assembly instructions for various operations.

5. **Address Specific Questions:**
    * **`.tq` ending:**  The code explicitly checks for this. The answer is that if the file ended with `.tq`, it would be a Torque source file.
    * **Relation to JavaScript:**  `MacroAssembler` is used in V8 to generate the machine code that executes JavaScript. So, these tests indirectly verify the correctness of the underlying architecture support for JavaScript execution.
    * **JavaScript Examples:**  Provide simple JavaScript examples that would rely on the tested functionalities. Byte swapping isn't directly exposed, but integer and float operations are.
    * **Code Logic Reasoning (Hypothetical):** Select a simple test case (`BYTESWAP`) and provide a concrete example of input and output based on the byte-swapping logic.
    * **Common Programming Errors:** Think about common errors related to the tested areas, like incorrect byte order assumptions or not handling potential overflow.
    * **Summary of Functionality (for Part 1):** Concisely summarize the key functionalities covered in the provided code snippet. Focus on the types of instructions and operations being tested.

6. **Structure the Response:** Organize the information logically, addressing each part of the prompt. Use clear headings and formatting. Emphasize key findings. Make sure the language is easy to understand.
这是对V8 JavaScript 引擎在 LoongArch64 架构上的宏汇编器进行功能测试的 C++ 代码文件。

**功能列举:**

该文件包含了多个测试用例，用于验证 `MacroAssembler` 类在 LoongArch64 架构上生成正确汇编代码的能力。  这些测试覆盖了以下功能：

* **字节交换 (BYTESWAP):** 测试 `ByteSwap` 指令，用于交换数据的字节序。
* **加载常量 (LoadConstants):** 测试加载各种常量值到寄存器的指令 (`li`)。
* **跳转表 (jump_tables4, jump_tables6):** 测试生成和使用跳转表的能力，包括处理跳转范围限制和生成跳转指令桩（trampoline）。
* **算术左移加法指令 (ALSL_W, ALSL_D):** 测试 `Alsl_w` (字) 和 `Alsl_d` (双字) 指令，它们执行算术左移后与另一个寄存器相加。
* **浮点数与整数转换指令 (Ffint_s_uw_Ftintrz_uw_s 等):** 测试各种浮点数和整数之间的转换指令，例如：
    * `Ffint_s_uw`: 将无符号字整数转换为单精度浮点数。
    * `Ftintrz_uw_s`: 将单精度浮点数截断为无符号字整数。
    * 以及双精度浮点数和有符号/无符号长整数之间的转换。
* **溢出检测指令 (OverflowInstructions):** 测试带有溢出检测的算术运算指令，例如 `AddOverflow_d` (双字加法溢出) 和 `MulOverflow_w` (字乘法溢出)。
* **最小值/最大值和 NaN 处理 (min_max_nan):** 测试浮点数的最小值 (`Float64Min`, `Float32Min`) 和最大值 (`Float64Max`, `Float32Max`) 指令，并验证对 NaN (非数字) 值的正确处理。
* **未对齐内存访问 (Unaligned):**  测试对未对齐内存地址进行读写操作的能力。

**关于文件后缀:**

如果 `v8/test/cctest/test-macro-assembler-loong64.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码**文件。Torque 是一种用于定义 V8 内部运行时函数的领域特定语言，它会被编译成 C++ 代码。

**与 JavaScript 的关系及示例:**

`MacroAssembler` 是 V8 引擎中用于生成机器码的关键组件。JavaScript 代码最终会被编译成机器码执行，而 `MacroAssembler` 就负责生成这些针对特定架构 (如 LoongArch64) 的指令。

以下是一些 JavaScript 示例，它们的功能与测试文件中测试的汇编指令有关：

* **字节交换:** 虽然 JavaScript 本身没有直接的字节交换操作，但在处理网络数据或二进制文件时，底层可能会用到字节交换。

```javascript
// 假设我们从网络接收到一个 32 位整数，需要转换字节序
function byteswap32(value) {
  return ((value & 0xFF) << 24) |
         ((value & 0xFF00) << 8) |
         ((value >> 8) & 0xFF00) |
         ((value >> 24) & 0xFF);
}

let networkValue = 0x01020304;
let hostValue = byteswap32(networkValue);
console.log(hostValue); // 在小端系统中，输出可能是 67305985 (0x04030201)
```

* **整数和浮点数运算:**  JavaScript 中的加法、减法、乘法以及浮点数运算等都会用到相应的机器指令。

```javascript
let a = 10;
let b = 5;
let sum = a + b; // 底层会使用加法指令
let product = a * b; // 底层会使用乘法指令

let float1 = 3.14;
let float2 = 2.71;
let floatSum = float1 + float2; // 底层会使用浮点加法指令
```

* **类型转换:** JavaScript 中 Number 和其他类型之间的转换会涉及到浮点数和整数之间的转换。

```javascript
let intValue = 10;
let floatValue = parseFloat(intValue); // 底层可能使用整数转浮点数的指令

let floatNum = 3.9;
let intNum = parseInt(floatNum); // 底层可能使用浮点数转整数的指令 (截断)
```

* **溢出:** JavaScript 中的算术运算在超出安全整数范围时可能会出现精度问题，虽然 JavaScript 不会像底层语言那样直接抛出溢出错误，但理解底层的溢出检测机制有助于理解其行为。

```javascript
let maxSafeInteger = Number.MAX_SAFE_INTEGER;
console.log(maxSafeInteger + 1);
console.log(maxSafeInteger + 2); // 可能会出现精度损失，因为超过了安全整数范围
```

* **最小值/最大值和 NaN:** JavaScript 中 `Math.min`, `Math.max` 以及 NaN 的处理。

```javascript
console.log(Math.min(5, 2)); // 输出 2
console.log(Math.max(5, 2)); // 输出 5
console.log(Math.min(5, NaN)); // 输出 NaN
console.log(Math.max(5, NaN)); // 输出 NaN
```

**代码逻辑推理 (假设输入与输出):**

以 `BYTESWAP` 测试为例，假设输入结构体 `T` 的内容如下：

* `t.s8` (uint64_t): `0x5612FFCD9D327ACC`
* `t.s4` (uint64_t, 实际存储 int32_t): `0x00000000781A15C3`
* `t.u4` (uint64_t, 实际存储 uint32_t): `0x000000000000FCDE`

在执行 `BYTESWAP` 测试后，预期结构体 `T` 的内容会变成（假设是小端系统）：

* `t.s8`: `0xCC7A329DCDFF1256`
* `t.s4`: `0xC3151A78`
* `t.u4`: `0xDEFC0000`

**用户常见的编程错误:**

* **字节序混淆:** 在处理跨平台或网络数据时，没有正确处理字节序转换，导致数据解析错误。例如，将网络字节序的数据直接当作本地字节序的数据处理。
* **整数溢出:** 在进行算术运算时，没有考虑到结果可能超出整数类型的表示范围，导致数据截断或错误的结果。在 JavaScript 中，虽然不会像 C++ 那样直接溢出，但超出安全整数范围会导致精度损失。
* **浮点数比较:**  直接使用 `==` 比较浮点数是否相等，由于浮点数的精度问题，可能会得到错误的结果。应该使用一个小的容差值进行比较。
* **NaN 的处理不当:**  没有正确判断和处理 NaN 值，导致程序逻辑错误。 `NaN !== NaN` 是一个需要注意的特性。
* **未对齐内存访问:**  在 C/C++ 等语言中，尝试访问未对齐的内存地址可能导致程序崩溃或性能下降。虽然高级语言通常会处理这个问题，但在进行底层编程或与硬件交互时需要注意。

**归纳功能 (第 1 部分):**

这部分代码主要测试了 `MacroAssembler` 在 LoongArch64 架构上生成 **字节交换指令、常量加载指令、以及涉及到跳转表的控制流指令** 的能力。它还涵盖了 **基本的算术左移加法指令**。  这些是构建更复杂代码生成功能的基础。

Prompt: 
```
这是目录为v8/test/cctest/test-macro-assembler-loong64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-macro-assembler-loong64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright 2021 the V8 project authors. All rights reserved.
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

#include <iostream>

#include "src/base/utils/random-number-generator.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/macro-assembler.h"
#include "src/compiler/access-builder.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/execution/simulator.h"
#include "src/objects/objects-inl.h"
#include "src/utils/ostreams.h"
#include "test/cctest/cctest.h"
#include "test/common/assembler-tester.h"

namespace v8 {
namespace internal {

// TODO(LOONG64): Refine these signatures per test case.
using FV = void*(int64_t x, int64_t y, int p2, int p3, int p4);
using F1 = void*(int x, int p1, int p2, int p3, int p4);
using F2 = void*(int x, int y, int p2, int p3, int p4);
using F3 = void*(void* p, int p1, int p2, int p3, int p4);
using F4 = void*(void* p0, void* p1, int p2, int p3, int p4);

#define __ masm->

TEST(BYTESWAP) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    uint64_t s8;
    uint64_t s4;
    uint64_t u4;
  };

  T t;
  // clang-format off
  uint64_t test_values[] = {0x5612FFCD9D327ACC,
                            0x781A15C3,
                            0xFCDE,
                            0x9F,
                            0xC81A15C3,
                            0x8000000000000000,
                            0xFFFFFFFFFFFFFFFF,
                            0x0000000080000000,
                            0x0000000000008000};
  // clang-format on
  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);

  MacroAssembler* masm = &assembler;

  __ Ld_d(a4, MemOperand(a0, offsetof(T, s8)));
  __ ByteSwap(a4, a4, 8);
  __ St_d(a4, MemOperand(a0, offsetof(T, s8)));

  __ Ld_d(a4, MemOperand(a0, offsetof(T, s4)));
  __ ByteSwap(a4, a4, 4);
  __ St_d(a4, MemOperand(a0, offsetof(T, s4)));

  __ Ld_d(a4, MemOperand(a0, offsetof(T, u4)));
  __ ByteSwap(a4, a4, 4);
  __ St_d(a4, MemOperand(a0, offsetof(T, u4)));

  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  masm->GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);

  for (size_t i = 0; i < arraysize(test_values); i++) {
    int32_t in_s4 = static_cast<int32_t>(test_values[i]);
    uint32_t in_u4 = static_cast<uint32_t>(test_values[i]);

    t.s8 = test_values[i];
    t.s4 = static_cast<uint64_t>(in_s4);
    t.u4 = static_cast<uint64_t>(in_u4);

    f.Call(&t, 0, 0, 0, 0);

    CHECK_EQ(ByteReverse<uint64_t>(test_values[i]), t.s8);
    CHECK_EQ(ByteReverse<int32_t>(in_s4), static_cast<int32_t>(t.s4));
    CHECK_EQ(ByteReverse<uint32_t>(in_u4), static_cast<uint32_t>(t.u4));
  }
}

TEST(LoadConstants) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope handles(isolate);

  int64_t refConstants[64];
  int64_t result[64];

  int64_t mask = 1;
  for (int i = 0; i < 64; i++) {
    refConstants[i] = ~(mask << i);
  }

  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;

  __ or_(a4, a0, zero_reg);
  for (int i = 0; i < 64; i++) {
    // Load constant.
    __ li(a5, Operand(refConstants[i]));
    __ St_d(a5, MemOperand(a4, zero_reg));
    __ Add_d(a4, a4, Operand(kSystemPointerSize));
  }

  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  masm->GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<FV>::FromCode(isolate, *code);
  (void)f.Call(reinterpret_cast<int64_t>(result), 0, 0, 0, 0);
  // Check results.
  for (int i = 0; i < 64; i++) {
    CHECK(refConstants[i] == result[i]);
  }
}

TEST(jump_tables4) {
  // Similar to test-assembler-loong64 jump_tables1, with extra test for branch
  // trampoline required before emission of the dd table (where trampolines are
  // blocked), and proper transition to long-branch mode.
  // Regression test for v8:4294.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;

  const int kNumCases = 512;
  int values[kNumCases];
  isolate->random_number_generator()->NextBytes(values, sizeof(values));
  Label labels[kNumCases];
  Label near_start, end, done;

  __ Push(ra);
  __ xor_(a2, a2, a2);

  __ Branch(&end);
  __ bind(&near_start);

  for (int i = 0; i < 32768 - 256; ++i) {
    __ Add_d(a2, a2, 1);
  }

  __ GenerateSwitchTable(a0, kNumCases,
                         [&labels](size_t i) { return labels + i; });

  for (int i = 0; i < kNumCases; ++i) {
    __ bind(&labels[i]);
    __ li(a2, values[i]);
    __ Branch(&done);
  }

  __ bind(&done);
  __ Pop(ra);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  __ bind(&end);
  __ Branch(&near_start);

  CodeDesc desc;
  masm->GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code);
#endif
  auto f = GeneratedCode<F1>::FromCode(isolate, *code);
  for (int i = 0; i < kNumCases; ++i) {
    int64_t res = reinterpret_cast<int64_t>(f.Call(i, 0, 0, 0, 0));
    ::printf("f(%d) = %" PRId64 "\n", i, res);
    CHECK_EQ(values[i], res);
  }
}

TEST(jump_tables6) {
  // Similar to test-assembler-loong64 jump_tables1, with extra test for branch
  // trampoline required after emission of the dd table (where trampolines are
  // blocked). This test checks if number of really generated instructions is
  // greater than number of counted instructions from code, as we are expecting
  // generation of trampoline in this case
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;

  const int kSwitchTableCases = 80;

  const int kMaxBranchOffset = (1 << (18 - 1)) - 1;
  const int kTrampolineSlotsSize = Assembler::kTrampolineSlotsSize;
  const int kSwitchTablePrologueSize = MacroAssembler::kSwitchTablePrologueSize;

  const int kMaxOffsetForTrampolineStart =
      kMaxBranchOffset - 16 * kTrampolineSlotsSize;
  const int kFillInstr = (kMaxOffsetForTrampolineStart / kInstrSize) -
                         (kSwitchTablePrologueSize + kSwitchTableCases) - 20;

  int values[kSwitchTableCases];
  isolate->random_number_generator()->NextBytes(values, sizeof(values));
  Label labels[kSwitchTableCases];
  Label near_start, end, done;

  __ Push(ra);
  __ xor_(a2, a2, a2);

  int offs1 = masm->pc_offset();
  int gen_insn = 0;

  __ Branch(&end);
  gen_insn += 1;
  __ bind(&near_start);

  for (int i = 0; i < kFillInstr; ++i) {
    __ Add_d(a2, a2, 1);
  }
  gen_insn += kFillInstr;

  __ GenerateSwitchTable(a0, kSwitchTableCases,
                         [&labels](size_t i) { return labels + i; });
  gen_insn += (kSwitchTablePrologueSize + kSwitchTableCases);

  for (int i = 0; i < kSwitchTableCases; ++i) {
    __ bind(&labels[i]);
    __ li(a2, values[i]);
    __ Branch(&done);
  }
  gen_insn += 3 * kSwitchTableCases;

  // If offset from here to first branch instr is greater than max allowed
  // offset for trampoline ...
  CHECK_LT(kMaxOffsetForTrampolineStart, masm->pc_offset() - offs1);
  // ... number of generated instructions must be greater then "gen_insn",
  // as we are expecting trampoline generation
  CHECK_LT(gen_insn, (masm->pc_offset() - offs1) / kInstrSize);

  __ bind(&done);
  __ Pop(ra);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  __ bind(&end);
  __ Branch(&near_start);

  CodeDesc desc;
  masm->GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code);
#endif
  auto f = GeneratedCode<F1>::FromCode(isolate, *code);
  for (int i = 0; i < kSwitchTableCases; ++i) {
    int64_t res = reinterpret_cast<int64_t>(f.Call(i, 0, 0, 0, 0));
    ::printf("f(%d) = %" PRId64 "\n", i, res);
    CHECK_EQ(values[i], res);
  }
}

static uint64_t run_alsl_w(uint32_t rj, uint32_t rk, int8_t sa) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;

  __ Alsl_w(a2, a0, a1, sa);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assembler.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F1>::FromCode(isolate, *code);

  uint64_t res = reinterpret_cast<uint64_t>(f.Call(rj, rk, 0, 0, 0));

  return res;
}

TEST(ALSL_W) {
  CcTest::InitializeVM();
  struct TestCaseAlsl {
    int32_t rj;
    int32_t rk;
    uint8_t sa;
    uint64_t expected_res;
  };
  // clang-format off
  struct TestCaseAlsl tc[] = {// rj, rk, sa, expected_res
                             {0x1, 0x4, 1, 0x6},
                             {0x1, 0x4, 2, 0x8},
                             {0x1, 0x4, 3, 0xC},
                             {0x1, 0x4, 4, 0x14},
                             {0x1, 0x4, 5, 0x24},
                             {0x1, 0x0, 1, 0x2},
                             {0x1, 0x0, 2, 0x4},
                             {0x1, 0x0, 3, 0x8},
                             {0x1, 0x0, 4, 0x10},
                             {0x1, 0x0, 5, 0x20},
                             {0x0, 0x4, 1, 0x4},
                             {0x0, 0x4, 2, 0x4},
                             {0x0, 0x4, 3, 0x4},
                             {0x0, 0x4, 4, 0x4},
                             {0x0, 0x4, 5, 0x4},

                             // Shift overflow.
                             {INT32_MAX, 0x4, 1, 0x2},
                             {INT32_MAX >> 1, 0x4, 2, 0x0},
                             {INT32_MAX >> 2, 0x4, 3, 0xFFFFFFFFFFFFFFFC},
                             {INT32_MAX >> 3, 0x4, 4, 0xFFFFFFFFFFFFFFF4},
                             {INT32_MAX >> 4, 0x4, 5, 0xFFFFFFFFFFFFFFE4},

                             // Signed addition overflow.
                             {0x1, INT32_MAX - 1, 1, 0xFFFFFFFF80000000},
                             {0x1, INT32_MAX - 3, 2, 0xFFFFFFFF80000000},
                             {0x1, INT32_MAX - 7, 3, 0xFFFFFFFF80000000},
                             {0x1, INT32_MAX - 15, 4, 0xFFFFFFFF80000000},
                             {0x1, INT32_MAX - 31, 5, 0xFFFFFFFF80000000},

                             // Addition overflow.
                             {0x1, -2, 1, 0x0},
                             {0x1, -4, 2, 0x0},
                             {0x1, -8, 3, 0x0},
                             {0x1, -16, 4, 0x0},
                             {0x1, -32, 5, 0x0}};
  // clang-format on
  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseAlsl);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    uint64_t res = run_alsl_w(tc[i].rj, tc[i].rk, tc[i].sa);
    PrintF("0x%" PRIx64 " =? 0x%" PRIx64 " == Alsl_w(a0, %x, %x, %hhu)\n",
           tc[i].expected_res, res, tc[i].rj, tc[i].rk, tc[i].sa);
    CHECK_EQ(tc[i].expected_res, res);
  }
}

static uint64_t run_alsl_d(uint64_t rj, uint64_t rk, int8_t sa) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;

  __ Alsl_d(a2, a0, a1, sa);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assembler.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<FV>::FromCode(isolate, *code);

  uint64_t res = reinterpret_cast<uint64_t>(f.Call(rj, rk, 0, 0, 0));

  return res;
}

TEST(ALSL_D) {
  CcTest::InitializeVM();
  struct TestCaseAlsl {
    int64_t rj;
    int64_t rk;
    uint8_t sa;
    uint64_t expected_res;
  };
  // clang-format off
  struct TestCaseAlsl tc[] = {// rj, rk, sa, expected_res
                             {0x1, 0x4, 1, 0x6},
                             {0x1, 0x4, 2, 0x8},
                             {0x1, 0x4, 3, 0xC},
                             {0x1, 0x4, 4, 0x14},
                             {0x1, 0x4, 5, 0x24},
                             {0x1, 0x0, 1, 0x2},
                             {0x1, 0x0, 2, 0x4},
                             {0x1, 0x0, 3, 0x8},
                             {0x1, 0x0, 4, 0x10},
                             {0x1, 0x0, 5, 0x20},
                             {0x0, 0x4, 1, 0x4},
                             {0x0, 0x4, 2, 0x4},
                             {0x0, 0x4, 3, 0x4},
                             {0x0, 0x4, 4, 0x4},
                             {0x0, 0x4, 5, 0x4},

                             // Shift overflow.
                             {INT64_MAX, 0x4, 1, 0x2},
                             {INT64_MAX >> 1, 0x4, 2, 0x0},
                             {INT64_MAX >> 2, 0x4, 3, 0xFFFFFFFFFFFFFFFC},
                             {INT64_MAX >> 3, 0x4, 4, 0xFFFFFFFFFFFFFFF4},
                             {INT64_MAX >> 4, 0x4, 5, 0xFFFFFFFFFFFFFFE4},

                             // Signed addition overflow.
                             {0x1, INT64_MAX - 1, 1, 0x8000000000000000},
                             {0x1, INT64_MAX - 3, 2, 0x8000000000000000},
                             {0x1, INT64_MAX - 7, 3, 0x8000000000000000},
                             {0x1, INT64_MAX - 15, 4, 0x8000000000000000},
                             {0x1, INT64_MAX - 31, 5, 0x8000000000000000},

                             // Addition overflow.
                             {0x1, -2, 1, 0x0},
                             {0x1, -4, 2, 0x0},
                             {0x1, -8, 3, 0x0},
                             {0x1, -16, 4, 0x0},
                             {0x1, -32, 5, 0x0}};
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseAlsl);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    uint64_t res = run_alsl_d(tc[i].rj, tc[i].rk, tc[i].sa);
    PrintF("0x%" PRIx64 " =? 0x%" PRIx64 " == Dlsa(v0, %" PRIx64 ", %" PRIx64
           ", %hhu)\n",
           tc[i].expected_res, res, tc[i].rj, tc[i].rk, tc[i].sa);
    CHECK_EQ(tc[i].expected_res, res);
  }
}
// clang-format off
static const std::vector<uint32_t> ffint_ftintrz_uint32_test_values() {
  static const uint32_t kValues[] = {0x00000000, 0x00000001, 0x00FFFF00,
                                     0x7FFFFFFF, 0x80000000, 0x80000001,
                                     0x80FFFF00, 0x8FFFFFFF, 0xFFFFFFFF};
  return std::vector<uint32_t>(&kValues[0], &kValues[arraysize(kValues)]);
}

static const std::vector<int32_t> ffint_ftintrz_int32_test_values() {
  static const int32_t kValues[] = {
      static_cast<int32_t>(0x00000000), static_cast<int32_t>(0x00000001),
      static_cast<int32_t>(0x00FFFF00), static_cast<int32_t>(0x7FFFFFFF),
      static_cast<int32_t>(0x80000000), static_cast<int32_t>(0x80000001),
      static_cast<int32_t>(0x80FFFF00), static_cast<int32_t>(0x8FFFFFFF),
      static_cast<int32_t>(0xFFFFFFFF)};
  return std::vector<int32_t>(&kValues[0], &kValues[arraysize(kValues)]);
}

static const std::vector<uint64_t> ffint_ftintrz_uint64_test_values() {
  static const uint64_t kValues[] = {
      0x0000000000000000, 0x0000000000000001, 0x0000FFFFFFFF0000,
      0x7FFFFFFFFFFFFFFF, 0x8000000000000000, 0x8000000000000001,
      0x8000FFFFFFFF0000, 0x8FFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF};
  return std::vector<uint64_t>(&kValues[0], &kValues[arraysize(kValues)]);
}

static const std::vector<int64_t> ffint_ftintrz_int64_test_values() {
  static const int64_t kValues[] = {static_cast<int64_t>(0x0000000000000000),
                                    static_cast<int64_t>(0x0000000000000001),
                                    static_cast<int64_t>(0x0000FFFFFFFF0000),
                                    static_cast<int64_t>(0x7FFFFFFFFFFFFFFF),
                                    static_cast<int64_t>(0x8000000000000000),
                                    static_cast<int64_t>(0x8000000000000001),
                                    static_cast<int64_t>(0x8000FFFFFFFF0000),
                                    static_cast<int64_t>(0x8FFFFFFFFFFFFFFF),
                                    static_cast<int64_t>(0xFFFFFFFFFFFFFFFF)};
  return std::vector<int64_t>(&kValues[0], &kValues[arraysize(kValues)]);
}
// clang-format on

// Helper macros that can be used in FOR_INT32_INPUTS(i) { ... *i ... }
#define FOR_INPUTS(ctype, itype, var, test_vector)           \
  std::vector<ctype> var##_vec = test_vector();              \
  for (std::vector<ctype>::iterator var = var##_vec.begin(); \
       var != var##_vec.end(); ++var)

#define FOR_INPUTS2(ctype, itype, var, var2, test_vector)  \
  std::vector<ctype> var##_vec = test_vector();            \
  std::vector<ctype>::iterator var;                        \
  std::vector<ctype>::reverse_iterator var2;               \
  for (var = var##_vec.begin(), var2 = var##_vec.rbegin(); \
       var != var##_vec.end(); ++var, ++var2)

#define FOR_ENUM_INPUTS(var, type, test_vector) \
  FOR_INPUTS(enum type, type, var, test_vector)
#define FOR_STRUCT_INPUTS(var, type, test_vector) \
  FOR_INPUTS(struct type, type, var, test_vector)
#define FOR_INT32_INPUTS(var, test_vector) \
  FOR_INPUTS(int32_t, int32, var, test_vector)
#define FOR_INT32_INPUTS2(var, var2, test_vector) \
  FOR_INPUTS2(int32_t, int32, var, var2, test_vector)
#define FOR_INT64_INPUTS(var, test_vector) \
  FOR_INPUTS(int64_t, int64, var, test_vector)
#define FOR_UINT32_INPUTS(var, test_vector) \
  FOR_INPUTS(uint32_t, uint32, var, test_vector)
#define FOR_UINT64_INPUTS(var, test_vector) \
  FOR_INPUTS(uint64_t, uint64, var, test_vector)

template <typename RET_TYPE, typename IN_TYPE, typename Func>
RET_TYPE run_CVT(IN_TYPE x, Func GenerateConvertInstructionFunc) {
  using F_CVT = RET_TYPE(IN_TYPE x0, int x1, int x2, int x3, int x4);

  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assm;

  GenerateConvertInstructionFunc(masm);
  __ movfr2gr_d(a2, f9);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F_CVT>::FromCode(isolate, *code);

  return reinterpret_cast<RET_TYPE>(f.Call(x, 0, 0, 0, 0));
}

TEST(Ffint_s_uw_Ftintrz_uw_s) {
  CcTest::InitializeVM();
  FOR_UINT32_INPUTS(i, ffint_ftintrz_uint32_test_values) {
    uint32_t input = *i;
    auto fn = [](MacroAssembler* masm) {
      __ Ffint_s_uw(f8, a0);
      __ movgr2frh_w(f9, zero_reg);
      __ Ftintrz_uw_s(f9, f8, f10);
    };
    CHECK_EQ(static_cast<float>(input), run_CVT<uint32_t>(input, fn));
  }
}

TEST(Ffint_s_ul_Ftintrz_ul_s) {
  CcTest::InitializeVM();
  FOR_UINT64_INPUTS(i, ffint_ftintrz_uint64_test_values) {
    uint64_t input = *i;
    auto fn = [](MacroAssembler* masm) {
      __ Ffint_s_ul(f8, a0);
      __ Ftintrz_ul_s(f9, f8, f10, a2);
    };
    CHECK_EQ(static_cast<float>(input), run_CVT<uint64_t>(input, fn));
  }
}

TEST(Ffint_d_uw_Ftintrz_uw_d) {
  CcTest::InitializeVM();
  FOR_UINT64_INPUTS(i, ffint_ftintrz_uint64_test_values) {
    uint32_t input = *i;
    auto fn = [](MacroAssembler* masm) {
      __ Ffint_d_uw(f8, a0);
      __ movgr2frh_w(f9, zero_reg);
      __ Ftintrz_uw_d(f9, f8, f10);
    };
    CHECK_EQ(static_cast<double>(input), run_CVT<uint32_t>(input, fn));
  }
}

TEST(Ffint_d_ul_Ftintrz_ul_d) {
  CcTest::InitializeVM();
  FOR_UINT64_INPUTS(i, ffint_ftintrz_uint64_test_values) {
    uint64_t input = *i;
    auto fn = [](MacroAssembler* masm) {
      __ Ffint_d_ul(f8, a0);
      __ Ftintrz_ul_d(f9, f8, f10, a2);
    };
    CHECK_EQ(static_cast<double>(input), run_CVT<uint64_t>(input, fn));
  }
}

TEST(Ffint_d_l_Ftintrz_l_ud) {
  CcTest::InitializeVM();
  FOR_INT64_INPUTS(i, ffint_ftintrz_int64_test_values) {
    int64_t input = *i;
    uint64_t abs_input = (input >= 0 || input == INT64_MIN) ? input : -input;
    auto fn = [](MacroAssembler* masm) {
      __ movgr2fr_d(f8, a0);
      __ ffint_d_l(f10, f8);
      __ Ftintrz_l_ud(f9, f10, f11);
    };
    CHECK_EQ(static_cast<double>(abs_input), run_CVT<uint64_t>(input, fn));
  }
}

TEST(ffint_d_l_Ftint_l_d) {
  CcTest::InitializeVM();
  FOR_INT64_INPUTS(i, ffint_ftintrz_int64_test_values) {
    int64_t input = *i;
    auto fn = [](MacroAssembler* masm) {
      __ movgr2fr_d(f8, a0);
      __ ffint_d_l(f10, f8);
      __ Ftintrz_l_d(f9, f10);
    };
    CHECK_EQ(static_cast<double>(input), run_CVT<int64_t>(input, fn));
  }
}

TEST(ffint_d_w_Ftint_w_d) {
  CcTest::InitializeVM();
  FOR_INT32_INPUTS(i, ffint_ftintrz_int32_test_values) {
    int32_t input = *i;
    auto fn = [](MacroAssembler* masm) {
      __ movgr2fr_w(f8, a0);
      __ ffint_d_w(f10, f8);
      __ Ftintrz_w_d(f9, f10);
      __ movfr2gr_s(a4, f9);
      __ movgr2fr_d(f9, a4);
    };
    CHECK_EQ(static_cast<double>(input), run_CVT<int64_t>(input, fn));
  }
}


static const std::vector<int64_t> overflow_int64_test_values() {
  // clang-format off
  static const int64_t kValues[] = {static_cast<int64_t>(0xF000000000000000),
                                    static_cast<int64_t>(0x0000000000000001),
                                    static_cast<int64_t>(0xFF00000000000000),
                                    static_cast<int64_t>(0x0000F00111111110),
                                    static_cast<int64_t>(0x0F00001000000000),
                                    static_cast<int64_t>(0x991234AB12A96731),
                                    static_cast<int64_t>(0xB0FFFF0F0F0F0F01),
                                    static_cast<int64_t>(0x00006FFFFFFFFFFF),
                                    static_cast<int64_t>(0xFFFFFFFFFFFFFFFF)};
  // clang-format on
  return std::vector<int64_t>(&kValues[0], &kValues[arraysize(kValues)]);
}

TEST(OverflowInstructions) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope handles(isolate);

  struct T {
    int64_t lhs;
    int64_t rhs;
    int64_t output_add1;
    int64_t output_add2;
    int64_t output_sub1;
    int64_t output_sub2;
    int64_t output_mul1;
    int64_t output_mul2;
    int64_t overflow_add1;
    int64_t overflow_add2;
    int64_t overflow_sub1;
    int64_t overflow_sub2;
    int64_t overflow_mul1;
    int64_t overflow_mul2;
  };
  T t;

  FOR_INT64_INPUTS(i, overflow_int64_test_values) {
    FOR_INT64_INPUTS(j, overflow_int64_test_values) {
      int64_t ii = *i;
      int64_t jj = *j;
      int64_t expected_add, expected_sub;
      int32_t ii32 = static_cast<int32_t>(ii);
      int32_t jj32 = static_cast<int32_t>(jj);
      int32_t expected_mul;
      int64_t expected_add_ovf, expected_sub_ovf, expected_mul_ovf;
      MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
      MacroAssembler* masm = &assembler;

      __ ld_d(t0, a0, offsetof(T, lhs));
      __ ld_d(t1, a0, offsetof(T, rhs));

      __ AddOverflow_d(t2, t0, Operand(t1), t3);
      __ st_d(t2, a0, offsetof(T, output_add1));
      __ st_d(t3, a0, offsetof(T, overflow_add1));
      __ or_(t3, zero_reg, zero_reg);
      __ AddOverflow_d(t0, t0, Operand(t1), t3);
      __ st_d(t0, a0, offsetof(T, output_add2));
      __ st_d(t3, a0, offsetof(T, overflow_add2));

      __ ld_d(t0, a0, offsetof(T, lhs));
      __ ld_d(t1, a0, offsetof(T, rhs));

      __ SubOverflow_d(t2, t0, Operand(t1), t3);
      __ st_d(t2, a0, offsetof(T, output_sub1));
      __ st_d(t3, a0, offsetof(T, overflow_sub1));
      __ or_(t3, zero_reg, zero_reg);
      __ SubOverflow_d(t0, t0, Operand(t1), t3);
      __ st_d(t0, a0, offsetof(T, output_sub2));
      __ st_d(t3, a0, offsetof(T, overflow_sub2));

      __ ld_d(t0, a0, offsetof(T, lhs));
      __ ld_d(t1, a0, offsetof(T, rhs));
      __ slli_w(t0, t0, 0);
      __ slli_w(t1, t1, 0);

      __ MulOverflow_w(t2, t0, Operand(t1), t3);
      __ st_d(t2, a0, offsetof(T, output_mul1));
      __ st_d(t3, a0, offsetof(T, overflow_mul1));
      __ or_(t3, zero_reg, zero_reg);
      __ MulOverflow_w(t0, t0, Operand(t1), t3);
      __ st_d(t0, a0, offsetof(T, output_mul2));
      __ st_d(t3, a0, offsetof(T, overflow_mul2));

      __ jirl(zero_reg, ra, 0);

      CodeDesc desc;
      masm->GetCode(isolate, &desc);
      Handle<Code> code =
          Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
      auto f = GeneratedCode<F3>::FromCode(isolate, *code);
      t.lhs = ii;
      t.rhs = jj;
      f.Call(&t, 0, 0, 0, 0);

      expected_add_ovf = base::bits::SignedAddOverflow64(ii, jj, &expected_add);
      expected_sub_ovf = base::bits::SignedSubOverflow64(ii, jj, &expected_sub);
      expected_mul_ovf =
          base::bits::SignedMulOverflow32(ii32, jj32, &expected_mul);

      CHECK_EQ(expected_add_ovf, t.overflow_add1 < 0);
      CHECK_EQ(expected_sub_ovf, t.overflow_sub1 < 0);
      CHECK_EQ(expected_mul_ovf, t.overflow_mul1 != 0);

      CHECK_EQ(t.overflow_add1, t.overflow_add2);
      CHECK_EQ(t.overflow_sub1, t.overflow_sub2);
      CHECK_EQ(t.overflow_mul1, t.overflow_mul2);

      CHECK_EQ(expected_add, t.output_add1);
      CHECK_EQ(expected_add, t.output_add2);
      CHECK_EQ(expected_sub, t.output_sub1);
      CHECK_EQ(expected_sub, t.output_sub2);
      if (!expected_mul_ovf) {
        CHECK_EQ(expected_mul, t.output_mul1);
        CHECK_EQ(expected_mul, t.output_mul2);
      }
    }
  }
}

TEST(min_max_nan) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;

  struct TestFloat {
    double a;
    double b;
    double c;
    double d;
    float e;
    float f;
    float g;
    float h;
  };

  TestFloat test;
  const double dnan = std::numeric_limits<double>::quiet_NaN();
  const double dinf = std::numeric_limits<double>::infinity();
  const double dminf = -std::numeric_limits<double>::infinity();
  const float fnan = std::numeric_limits<float>::quiet_NaN();
  const float finf = std::numeric_limits<float>::infinity();
  const float fminf = -std::numeric_limits<float>::infinity();
  const int kTableLength = 13;

  // clang-format off
  double inputsa[kTableLength] = {dnan,  3.0,  -0.0, 0.0,  42.0, dinf, dminf,
                                  dinf, dnan, 3.0,  dinf, dnan, dnan};
  double inputsb[kTableLength] = {dnan,   2.0, 0.0,  -0.0, dinf, 42.0, dinf,
                                  dminf, 3.0, dnan, dnan, dinf, dnan};
  double outputsdmin[kTableLength] = {dnan,  2.0,   -0.0,  -0.0, 42.0,
                                      42.0, dminf, dminf, dnan, dnan,
                                      dnan, dnan,  dnan};
  double outputsdmax[kTableLength] = {dnan,  3.0,  0.0,  0.0,  dinf, dinf, dinf,
                                      dinf, dnan, dnan, dnan, dnan, dnan};

  float inputse[kTableLength] = {2.0,  3.0,  -0.0, 0.0,  42.0, finf, fminf,
                                 finf, fnan, 3.0,  finf, fnan, fnan};
  float inputsf[kTableLength] = {3.0,   2.0, 0.0,  -0.0, finf, 42.0, finf,
                                 fminf, 3.0, fnan, fnan, finf, fnan};
  float outputsfmin[kTableLength] = {2.0,   2.0,  -0.0, -0.0, 42.0, 42.0, fminf,
                                     fminf, fnan, fnan, fnan, fnan, fnan};
  float outputsfmax[kTableLength] = {3.0,  3.0,  0.0,  0.0,  finf, finf, finf,
                                     finf, fnan, fnan, fnan, fnan, fnan};

  // clang-format on
  auto handle_dnan = [masm](FPURegister dst, Label* nan, Label* back) {
    __ bind(nan);
    __ LoadRoot(t8, RootIndex::kNanValue);
    __ Fld_d(dst,
             FieldMemOperand(
                 t8, compiler::AccessBuilder::ForHeapNumberValue().offset));
    __ Branch(back);
  };

  auto handle_snan = [masm, fnan](FPURegister dst, Label* nan, Label* back) {
    __ bind(nan);
    __ Move(dst, fnan);
    __ Branch(back);
  };

  Label handle_mind_nan, handle_maxd_nan, handle_mins_nan, handle_maxs_nan;
  Label back_mind_nan, back_maxd_nan, back_mins_nan, back_maxs_nan;

  __ Push(s6);
#ifdef V8_COMPRESS_POINTERS
  __ Push(s8);
#endif
  __ InitializeRootRegister();
  __ Fld_d(f8, MemOperand(a0, offsetof(TestFloat, a)));
  __ Fld_d(f9, MemOperand(a0, offsetof(TestFloat, b)));
  __ Fld_s(f10, MemOperand(a0, offsetof(TestFloat, e)));
  __ Fld_s(f11, MemOperand(a0, offsetof(TestFloat, f)));
  __ Float64Min(f12, f8, f9, &handle_mind_nan);
  __ bind(&back_mind_nan);
  __ Float64Max(f13, f8, f9, &handle_maxd_nan);
  __ bind(&back_maxd_nan);
  __ Float32Min(f14, f10, f11, &handle_mins_nan);
  __ bind(&back_mins_nan);
  __ Float32Max(f15, f10, f11, &handle_maxs_nan);
  __ bind(&back_maxs_nan);
  __ Fst_d(f12, MemOperand(a0, offsetof(TestFloat, c)));
  __ Fst_d(f13, MemOperand(a0, offsetof(TestFloat, d)));
  __ Fst_s(f14, MemOperand(a0, offsetof(TestFloat, g)));
  __ Fst_s(f15, MemOperand(a0, offsetof(TestFloat, h)));
#ifdef V8_COMPRESS_POINTERS
  __ Pop(s8);
#endif
  __ Pop(s6);
  __ jirl(zero_reg, ra, 0);

  handle_dnan(f12, &handle_mind_nan, &back_mind_nan);
  handle_dnan(f13, &handle_maxd_nan, &back_maxd_nan);
  handle_snan(f14, &handle_mins_nan, &back_mins_nan);
  handle_snan(f15, &handle_maxs_nan, &back_maxs_nan);

  CodeDesc desc;
  masm->GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  for (int i = 0; i < kTableLength; i++) {
    test.a = inputsa[i];
    test.b = inputsb[i];
    test.e = inputse[i];
    test.f = inputsf[i];

    f.Call(&test, 0, 0, 0, 0);
    CHECK_EQ(0, memcmp(&test.c, &outputsdmin[i], sizeof(test.c)));
    CHECK_EQ(0, memcmp(&test.d, &outputsdmax[i], sizeof(test.d)));
    CHECK_EQ(0, memcmp(&test.g, &outputsfmin[i], sizeof(test.g)));
    CHECK_EQ(0, memcmp(&test.h, &outputsfmax[i], sizeof(test.h)));
  }
}

template <typename IN_TYPE, typename Func>
bool run_Unaligned(char* memory_buffer, int32_t in_offset, int32_t out_offset,
                   IN_TYPE value, Func GenerateUnalignedInstructionFunc) {
  using F_CVT = int32_t(char* x0, int x1, int x2, int x3, int x4);

  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assm;
  IN_TYPE res;

  GenerateUnalignedInstructionFunc(masm, in_offset, out_offset);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F_CVT>::FromCode(isolate, *code);

  MemCopy(memory_buffer + in_offset, &value, sizeof(IN_TYPE));
  f.Call(memory_buffer, 0, 0, 0, 0);
  MemCopy(&res, memory_buffer + out_offset, sizeof(IN_TYPE));

  return res == value;
}

static const std::vector<uint64_t> unsigned_test_values() {
  // clang-format o
"""


```