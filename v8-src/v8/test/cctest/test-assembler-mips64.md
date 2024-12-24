Response: The user has provided the first part of a C++ source code file and wants a summary of its functionality. The file path `v8/test/cctest/test-assembler-mips64.cc` strongly suggests that this file contains tests for the MIPS64 assembler within the V8 JavaScript engine.

Here's a breakdown of the thought process to summarize the functionality:

1. **Identify the Core Purpose:** The file name and the `TEST` macros immediately indicate that this is a test file. The `mips64` part specifies the target architecture. The `assembler` part tells us it's testing the code generation capabilities for that architecture.

2. **Examine Includes:** The included headers provide clues:
    * `iostream`: Basic input/output.
    * `src/base/utils/random-number-generator.h`:  Might be used for generating random test cases (though not evident in this part).
    * `src/codegen/assembler-inl.h`, `src/codegen/macro-assembler.h`:  Confirms this is about assembly code generation. `MacroAssembler` is the key class being tested.
    * `src/diagnostics/disassembler.h`: Suggests the tests might involve inspecting the generated assembly code.
    * `src/execution/simulator.h`:  Implies that the generated assembly is being run in a simulator, not on real hardware.
    * `src/heap/factory.h`: Indicates interaction with V8's object allocation.
    * `src/init/v8.h`:  Essential for initializing the V8 environment.
    * `test/cctest/cctest.h`: The testing framework used in V8.

3. **Analyze the `using` Statements:** `using F1` through `F5` define function pointer types. These likely represent the signatures of the assembly code snippets being tested. The parameter types (int, int64_t, void*) hint at the kind of operations being performed.

4. **Deconstruct Individual Tests:** Each `TEST(MIPS...)` block represents an individual test case. Look for patterns within these tests:
    * **Initialization:** `CcTest::InitializeVM()`, `Isolate* isolate = ...`, `HandleScope scope(...)`, `MacroAssembler assm(...)`. This is the standard setup for V8 tests.
    * **Assembly Generation:** The `__ ...` calls (e.g., `__ addu(v0, a0, a1)`) are emitting MIPS64 assembly instructions using the `MacroAssembler`.
    * **Code Object Creation:** `assm.GetCode(...)`, `Factory::CodeBuilder(...)->Build()`. This compiles the generated assembly into executable code within V8.
    * **Execution:** `GeneratedCode<F...>::FromCode(...)`, `f.Call(...)`. The generated code is being executed.
    * **Verification:** `CHECK_EQ(...)`. The results of the executed assembly are compared against expected values.

5. **Identify Specific Instruction Coverage:**  Scan through the assembly instructions being used in each test. This part covers:
    * Basic arithmetic (`addu`, `addiu`, `subu`)
    * Data movement (`mov`, `li`)
    * Control flow (`b`, `Branch`, `jr`)
    * Bitwise operations (`xori`, `and_`, `or_`, `xor_`, `nor`)
    * Shifts (`srl`, `sll`, `sra`, `srav`, `sllv`, `srlv`, `dsll32`, `dsrl32`)
    * Comparisons (`slt`, `sltu`, `slti`, `sltiu`)
    * Immediate operations (`andi`, `ori`, `xori`, `lui`)
    * Bit manipulation (`Clz`, `Movn`, `Ins`, `Movz`, `Ext`)
    * Floating-point operations (starting with `TEST(MIPS3)`): loads (`Ldc1`, `Lwc1`), stores (`Sdc1`, `Swc1`), arithmetic (`add_d`, `sub_d`, `mul_d`, `div_d`, `sqrt_d`, `add_s`, `sub_s`, `mul_s`, `div_s`, `sqrt_s`), conversions (`cvt_d_w`, `cvt_s_w`), conditional moves (MIPS-R6).
    * Memory loads and stores (`Lw`, `Sw`, `Lh`, `Lhu`, `Lb`, `Sh`, `Sd`, `Lwu`, `lwl`, `lwr`, `swl`, `swr`).
    * Conversions between doubles and integers/longs (`cvt_w_d`, `cvt_d_w`, `cvt_l_d`, `cvt_d_l`).
    * Rounding and truncation (`round_w_d`, `floor_w_d`, `ceil_w_d`, `trunc_w_d`, `cvt_w_d`).
    * Conditional branching based on floating-point comparisons.
    * Rotate instructions (`rotr`, `rotrv`).
    * Select instructions (`seleqz`, `selnez`, `sel`).
    * Min/Max instructions (`min_d`, `max_d`, `min_s`, `max_s`, `mina_d`, `maxa_d`, `mina_s`, `maxa_s`).
    * Rounding to integer (`rint_d`, `rint_s`).

6. **Connect to JavaScript:**  Realize that the tested assembly instructions are the low-level implementation of JavaScript features. Consider how common JavaScript operations might map to these instructions.

7. **Formulate the Summary:** Combine the observations into a concise description of the file's purpose and relate it to JavaScript functionality.

8. **Create JavaScript Examples:**  Invent simple JavaScript code snippets that would likely result in the generation of some of the tested MIPS64 instructions. Focus on arithmetic, comparisons, and basic data types.
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

#include "src/base/utils/random-number-generator.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/macro-assembler.h"
#include "src/diagnostics/disassembler.h"
#include "src/execution/simulator.h"
#include "src/heap/factory.h"
#include "src/init/v8.h"
#include "test/cctest/cctest.h"

namespace v8 {
namespace internal {

// Define these function prototypes to match JSEntryFunction in execution.cc.
// TODO(mips64): Refine these signatures per test case.
using F1 = void*(int x, int p1, int p2, int p3, int p4);
using F2 = void*(int x, int y, int p2, int p3, int p4);
using F3 = void*(void* p, int p1, int p2, int p3, int p4);
using F4 = void*(int64_t x, int64_t y, int64_t p2, int64_t p3, int64_t p4);
using F5 = void*(void* p0, void* p1, int p2, int p3, int p4);

#define __ assm.

TEST(MIPS0) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  // Addition.
  __ addu(v0, a0, a1);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  int64_t res = reinterpret_cast<int64_t>(f.Call(0xAB0, 0xC, 0, 0, 0));
  CHECK_EQ(0xABCL, res);
}

TEST(MIPS1) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  Label L, C;

  __ mov(a1, a0);
  __ li(v0, 0l);
  __ b(&C);
  __ nop();

  __ bind(&L);
  __ addu(v0, v0, a1);
  __ addiu(a1, a1, -1);

  __ bind(&C);
  __ xori(v1, a1, 0);
  __ Branch(&L, ne, v1, Operand((int64_t)0));
  __ nop();

  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F1>::FromCode(isolate, *code);
  int64_t res = reinterpret_cast<int64_t>(f.Call(50, 0, 0, 0, 0));
  CHECK_EQ(1275L, res);
}

TEST(MIPS2) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label exit, error;

  // ----- Test all instructions.

  // Test lui, ori, and addiu, used in the li pseudo-instruction.
  // This way we can then safely load registers with chosen values.

  __ ori(a4, zero_reg, 0);
  __ lui(a4, 0x1234);
  __ ori(a4, a4, 0);
  __ ori(a4, a4, 0x0F0F);
  __ ori(a4, a4, 0xF0F0);
  __ addiu(a5, a4, 1);
  __ addiu(a6, a5, -0x10);

  // Load values in temporary registers.
  __ li(a4, 0x00000004);
  __ li(a5, 0x00001234);
  __ li(a6, 0x12345678);
  __ li(a7, 0x7FFFFFFF);
  __ li(t0, 0xFFFFFFFC);
  __ li(t1, 0xFFFFEDCC);
  __ li(t2, 0xEDCBA988);
  __ li(t3, 0x80000000);

  // SPECIAL class.
  __ srl(v0, a6, 8);    // 0x00123456
  __ sll(v0, v0, 11);   // 0x91A2B000
  __ sra(v0, v0, 3);    // 0xF2345600
  __ srav(v0, v0, a4);  // 0xFF234560
  __ sllv(v0, v0, a4);  // 0xF2345600
  __ srlv(v0, v0, a4);  // 0x0F234560
  __ Branch(&error, ne, v0, Operand(0x0F234560));
  __ nop();

  __ addu(v0, a4, a5);  // 0x00001238
  __ subu(v0, v0, a4);  // 0x00001234
  __ Branch(&error, ne, v0, Operand(0x00001234));
  __ nop();
  __ addu(v1, a7, a4);  // 32bit addu result is sign-extended into 64bit reg.
  __ Branch(&error, ne, v1, Operand(0xFFFFFFFF80000003));
  __ nop();
  __ subu(v1, t3, a4);  // 0x7FFFFFFC
  __ Branch(&error, ne, v1, Operand(0x7FFFFFFC));
  __ nop();

  __ and_(v0, a5, a6);  // 0x0000000000001230
  __ or_(v0, v0, a5);   // 0x0000000000001234
  __ xor_(v0, v0, a6);  // 0x000000001234444C
  __ nor(v0, v0, a6);   // 0xFFFFFFFFEDCBA987
  __ Branch(&error, ne, v0, Operand(0xFFFFFFFFEDCBA983));
  __ nop();

  // Shift both 32bit number to left, to preserve meaning of next comparison.
  __ dsll32(a7, a7, 0);
  __ dsll32(t3, t3, 0);

  __ slt(v0, t3, a7);
  __ Branch(&error, ne, v0, Operand(0x1));
  __ nop();
  __ sltu(v0, t3, a7);
  __ Branch(&error, ne, v0, Operand(zero_reg));
  __ nop();

  // Restore original values in registers.
  __ dsrl32(a7, a7, 0);
  __ dsrl32(t3, t3, 0);
  // End of SPECIAL class.

  __ addiu(v0, zero_reg, 0x7421);  // 0x00007421
  __ addiu(v0, v0, -0x1);          // 0x00007420
  __ addiu(v0, v0, -0x20);         // 0x00007400
  __ Branch(&error, ne, v0, Operand(0x00007400));
  __ nop();
  __ addiu(v1, a7, 0x1);  // 0x80000000 - result is sign-extended.
  __ Branch(&error, ne, v1, Operand(0xFFFFFFFF80000000));
  __ nop();

  __ slti(v0, a5, 0x00002000);  // 0x1
  __ slti(v0, v0, 0xFFFF8000);  // 0x0
  __ Branch(&error, ne, v0, Operand(zero_reg));
  __ nop();
  __ sltiu(v0, a5, 0x00002000);  // 0x1
  __ sltiu(v0, v0, 0x00008000);  // 0x1
  __ Branch(&error, ne, v0, Operand(0x1));
  __ nop();

  __ andi(v0, a5, 0xF0F0);  // 0x00001030
  __ ori(v0, v0, 0x8A00);   // 0x00009A30
  __ xori(v0, v0, 0x83CC);  // 0x000019FC
  __ Branch(&error, ne, v0, Operand(0x000019FC));
  __ nop();
  __ lui(v1, 0x8123);  // Result is sign-extended into 64bit register.
  __ Branch(&error, ne, v1, Operand(0xFFFFFFFF81230000));
  __ nop();

  // Bit twiddling instructions & conditional moves.
  // Uses a4-t3 as set above.
  __ Clz(v0, a4);       // 29
  __ Clz(v1, a5);       // 19
  __ addu(v0, v0, v1);  // 48
  __ Clz(v1, a6);       // 3
  __ addu(v0, v0, v1);  // 51
  __ Clz(v1, t3);       // 0
  __ addu(v0, v0, v1);  // 51
  __ Branch(&error, ne, v0, Operand(51));
  __ Movn(a0, a7, a4);  // Move a0<-a7 (a4 is NOT 0).
  __ Ins(a0, a5, 12, 8);  // 0x7FF34FFF
  __ Branch(&error, ne, a0, Operand(0x7FF34FFF));
  __ Movz(a0, t2, t3);    // a0 not updated (t3 is NOT 0).
  __ Ext(a1, a0, 8, 12);  // 0x34F
  __ Branch(&error, ne, a1, Operand(0x34F));
  __ Movz(a0, t2, v1);    // a0<-t2, v0 is 0, from 8 instr back.
  __ Branch(&error, ne, a0, Operand(t2));

  // Everything was correctly executed. Load the expected result.
  __ li(v0, 0x31415926);
  __ b(&exit);
  __ nop();

  __ bind(&error);
  // Got an error. Return a wrong result.
  __ li(v0, 666);

  __ bind(&exit);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  int64_t res = reinterpret_cast<int64_t>(f.Call(0xAB0, 0xC, 0, 0, 0));

  CHECK_EQ(0x31415926L, res);
}
```

### 功能归纳:

这个C++源代码文件是 **V8 JavaScript 引擎** 的一部分，专门用于测试 **MIPS64 架构** 的 **汇编器 (assembler)** 功能。

具体来说，这第1部分（共7部分）主要包含以下功能：

1. **初始化测试环境:** 它使用 `CcTest::InitializeVM()` 初始化 V8 虚拟机，并创建 `Isolate` 和 `HandleScope` 用于内存管理。
2. **创建 MacroAssembler 对象:**  它使用 `MacroAssembler` 类来生成 MIPS64 汇编指令序列。
3. **测试基本的 MIPS64 指令:**  它编写了一系列测试用例 (`TEST(MIPS0)`, `TEST(MIPS1)`, `TEST(MIPS2)`)，每个测试用例都生成一小段 MIPS64 汇编代码，用于测试不同的指令，例如：
    * **算术运算:** `addu`, `addiu`, `subu`
    * **数据移动:** `mov`, `li` (伪指令)
    * **控制流:** `b` (branch), `Branch` (条件分支), `jr` (jump register)
    * **位运算:** `xori`, `and_`, `or_`, `xor_`, `nor`
    * **移位运算:** `srl`, `sll`, `sra`, `srav`, `sllv`, `srlv`, `dsll32`, `dsrl32`
    * **比较运算:** `slt`, `sltu`, `slti`, `sltiu`
    * **立即数运算:** `andi`, `ori`, `xori`, `lui`
    * **位字段操作和条件移动:** `Clz`, `Movn`, `Ins`, `Movz`, `Ext`
4. **生成可执行代码:** 使用 `assm.GetCode()` 获取生成的汇编代码的描述，然后使用 `Factory::CodeBuilder` 将其构建为可执行的 `Code` 对象。
5. **执行生成的代码:**  使用 `GeneratedCode` 模板类将 `Code` 对象转换为可调用的函数指针，并通过 `f.Call()` 执行生成的机器码。
6. **验证执行结果:** 使用 `CHECK_EQ` 宏来断言生成的代码的执行结果是否与预期值相符，从而验证汇编器是否正确地生成了指令。

### 与 JavaScript 的关系及示例:

虽然这个文件直接操作的是汇编代码，但它与 JavaScript 的功能息息相关。 **V8 引擎负责将 JavaScript 代码编译成机器码执行**，而这个文件测试的汇编器正是这个编译过程中的重要组成部分。

例如，以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

let result = add(0xAB0, 0xC);
```

当 V8 引擎执行这段代码时，`add` 函数中的加法运算 `a + b` 就可能被编译成类似 `TEST(MIPS0)` 中测试的 `addu` MIPS64 指令。

再比如，以下 JavaScript 中的循环结构：

```javascript
let sum = 0;
for (let i = 0; i < 50; i++) {
  sum += i;
}
```

在编译时，`for` 循环的条件判断 (`i < 50`) 和循环体的加法运算 (`sum += i`) 可能会被翻译成类似 `TEST(MIPS1)` 中使用的条件分支 (`Branch`) 和加法指令 (`addu`, `addiu`)。

`TEST(MIPS2)` 中测试的各种位运算指令，例如 `&` (AND), `|` (OR), `^` (XOR), `~` (NOT), `<<` (左移), `>>` (右移) 等，都对应着 JavaScript 中的位运算符。

**总结:** 这个文件的目的是确保 V8 引擎在 MIPS64 架构下能够正确地将 JavaScript 代码编译成高效且正确的机器码。它通过编写针对特定汇编指令的测试用例，来验证汇编器的正确性和功能完整性。

Prompt: 
```
这是目录为v8/test/cctest/test-assembler-mips64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共7部分，请归纳一下它的功能

"""
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

#include "src/base/utils/random-number-generator.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/macro-assembler.h"
#include "src/diagnostics/disassembler.h"
#include "src/execution/simulator.h"
#include "src/heap/factory.h"
#include "src/init/v8.h"
#include "test/cctest/cctest.h"

namespace v8 {
namespace internal {

// Define these function prototypes to match JSEntryFunction in execution.cc.
// TODO(mips64): Refine these signatures per test case.
using F1 = void*(int x, int p1, int p2, int p3, int p4);
using F2 = void*(int x, int y, int p2, int p3, int p4);
using F3 = void*(void* p, int p1, int p2, int p3, int p4);
using F4 = void*(int64_t x, int64_t y, int64_t p2, int64_t p3, int64_t p4);
using F5 = void*(void* p0, void* p1, int p2, int p3, int p4);

#define __ assm.

TEST(MIPS0) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  // Addition.
  __ addu(v0, a0, a1);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  int64_t res = reinterpret_cast<int64_t>(f.Call(0xAB0, 0xC, 0, 0, 0));
  CHECK_EQ(0xABCL, res);
}


TEST(MIPS1) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  Label L, C;

  __ mov(a1, a0);
  __ li(v0, 0l);
  __ b(&C);
  __ nop();

  __ bind(&L);
  __ addu(v0, v0, a1);
  __ addiu(a1, a1, -1);

  __ bind(&C);
  __ xori(v1, a1, 0);
  __ Branch(&L, ne, v1, Operand((int64_t)0));
  __ nop();

  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F1>::FromCode(isolate, *code);
  int64_t res = reinterpret_cast<int64_t>(f.Call(50, 0, 0, 0, 0));
  CHECK_EQ(1275L, res);
}


TEST(MIPS2) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label exit, error;

  // ----- Test all instructions.

  // Test lui, ori, and addiu, used in the li pseudo-instruction.
  // This way we can then safely load registers with chosen values.

  __ ori(a4, zero_reg, 0);
  __ lui(a4, 0x1234);
  __ ori(a4, a4, 0);
  __ ori(a4, a4, 0x0F0F);
  __ ori(a4, a4, 0xF0F0);
  __ addiu(a5, a4, 1);
  __ addiu(a6, a5, -0x10);

  // Load values in temporary registers.
  __ li(a4, 0x00000004);
  __ li(a5, 0x00001234);
  __ li(a6, 0x12345678);
  __ li(a7, 0x7FFFFFFF);
  __ li(t0, 0xFFFFFFFC);
  __ li(t1, 0xFFFFEDCC);
  __ li(t2, 0xEDCBA988);
  __ li(t3, 0x80000000);

  // SPECIAL class.
  __ srl(v0, a6, 8);    // 0x00123456
  __ sll(v0, v0, 11);   // 0x91A2B000
  __ sra(v0, v0, 3);    // 0xF2345600
  __ srav(v0, v0, a4);  // 0xFF234560
  __ sllv(v0, v0, a4);  // 0xF2345600
  __ srlv(v0, v0, a4);  // 0x0F234560
  __ Branch(&error, ne, v0, Operand(0x0F234560));
  __ nop();

  __ addu(v0, a4, a5);  // 0x00001238
  __ subu(v0, v0, a4);  // 0x00001234
  __ Branch(&error, ne, v0, Operand(0x00001234));
  __ nop();
  __ addu(v1, a7, a4);  // 32bit addu result is sign-extended into 64bit reg.
  __ Branch(&error, ne, v1, Operand(0xFFFFFFFF80000003));
  __ nop();
  __ subu(v1, t3, a4);  // 0x7FFFFFFC
  __ Branch(&error, ne, v1, Operand(0x7FFFFFFC));
  __ nop();

  __ and_(v0, a5, a6);  // 0x0000000000001230
  __ or_(v0, v0, a5);   // 0x0000000000001234
  __ xor_(v0, v0, a6);  // 0x000000001234444C
  __ nor(v0, v0, a6);   // 0xFFFFFFFFEDCBA987
  __ Branch(&error, ne, v0, Operand(0xFFFFFFFFEDCBA983));
  __ nop();

  // Shift both 32bit number to left, to preserve meaning of next comparison.
  __ dsll32(a7, a7, 0);
  __ dsll32(t3, t3, 0);

  __ slt(v0, t3, a7);
  __ Branch(&error, ne, v0, Operand(0x1));
  __ nop();
  __ sltu(v0, t3, a7);
  __ Branch(&error, ne, v0, Operand(zero_reg));
  __ nop();

  // Restore original values in registers.
  __ dsrl32(a7, a7, 0);
  __ dsrl32(t3, t3, 0);
  // End of SPECIAL class.

  __ addiu(v0, zero_reg, 0x7421);  // 0x00007421
  __ addiu(v0, v0, -0x1);          // 0x00007420
  __ addiu(v0, v0, -0x20);         // 0x00007400
  __ Branch(&error, ne, v0, Operand(0x00007400));
  __ nop();
  __ addiu(v1, a7, 0x1);  // 0x80000000 - result is sign-extended.
  __ Branch(&error, ne, v1, Operand(0xFFFFFFFF80000000));
  __ nop();

  __ slti(v0, a5, 0x00002000);  // 0x1
  __ slti(v0, v0, 0xFFFF8000);  // 0x0
  __ Branch(&error, ne, v0, Operand(zero_reg));
  __ nop();
  __ sltiu(v0, a5, 0x00002000);  // 0x1
  __ sltiu(v0, v0, 0x00008000);  // 0x1
  __ Branch(&error, ne, v0, Operand(0x1));
  __ nop();

  __ andi(v0, a5, 0xF0F0);  // 0x00001030
  __ ori(v0, v0, 0x8A00);   // 0x00009A30
  __ xori(v0, v0, 0x83CC);  // 0x000019FC
  __ Branch(&error, ne, v0, Operand(0x000019FC));
  __ nop();
  __ lui(v1, 0x8123);  // Result is sign-extended into 64bit register.
  __ Branch(&error, ne, v1, Operand(0xFFFFFFFF81230000));
  __ nop();

  // Bit twiddling instructions & conditional moves.
  // Uses a4-t3 as set above.
  __ Clz(v0, a4);       // 29
  __ Clz(v1, a5);       // 19
  __ addu(v0, v0, v1);  // 48
  __ Clz(v1, a6);       // 3
  __ addu(v0, v0, v1);  // 51
  __ Clz(v1, t3);       // 0
  __ addu(v0, v0, v1);  // 51
  __ Branch(&error, ne, v0, Operand(51));
  __ Movn(a0, a7, a4);  // Move a0<-a7 (a4 is NOT 0).
  __ Ins(a0, a5, 12, 8);  // 0x7FF34FFF
  __ Branch(&error, ne, a0, Operand(0x7FF34FFF));
  __ Movz(a0, t2, t3);    // a0 not updated (t3 is NOT 0).
  __ Ext(a1, a0, 8, 12);  // 0x34F
  __ Branch(&error, ne, a1, Operand(0x34F));
  __ Movz(a0, t2, v1);    // a0<-t2, v0 is 0, from 8 instr back.
  __ Branch(&error, ne, a0, Operand(t2));

  // Everything was correctly executed. Load the expected result.
  __ li(v0, 0x31415926);
  __ b(&exit);
  __ nop();

  __ bind(&error);
  // Got an error. Return a wrong result.
  __ li(v0, 666);

  __ bind(&exit);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  int64_t res = reinterpret_cast<int64_t>(f.Call(0xAB0, 0xC, 0, 0, 0));

  CHECK_EQ(0x31415926L, res);
}


TEST(MIPS3) {
  // Test floating point instructions.
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
    double i;
    float fa;
    float fb;
    float fc;
    float fd;
    float fe;
    float ff;
    float fg;
  };
  T t;

  // Create a function that accepts &t, and loads, manipulates, and stores
  // the doubles t.a ... t.f.
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  // Double precision floating point instructions.
  __ Ldc1(f4, MemOperand(a0, offsetof(T, a)));
  __ Ldc1(f6, MemOperand(a0, offsetof(T, b)));
  __ add_d(f8, f4, f6);
  __ Sdc1(f8, MemOperand(a0, offsetof(T, c)));  // c = a + b.

  __ mov_d(f10, f8);  // c
  __ neg_d(f12, f6);  // -b
  __ sub_d(f10, f10, f12);
  __ Sdc1(f10, MemOperand(a0, offsetof(T, d)));  // d = c - (-b).

  __ Sdc1(f4, MemOperand(a0, offsetof(T, b)));  // b = a.

  __ li(a4, 120);
  __ mtc1(a4, f14);
  __ cvt_d_w(f14, f14);   // f14 = 120.0.
  __ mul_d(f10, f10, f14);
  __ Sdc1(f10, MemOperand(a0, offsetof(T, e)));  // e = d * 120 = 1.8066e16.

  __ div_d(f12, f10, f4);
  __ Sdc1(f12, MemOperand(a0, offsetof(T, f)));  // f = e / a = 120.44.

  __ sqrt_d(f14, f12);
  __ Sdc1(f14, MemOperand(a0, offsetof(T, g)));
  // g = sqrt(f) = 10.97451593465515908537

  if (kArchVariant == kMips64r2) {
    __ Ldc1(f4, MemOperand(a0, offsetof(T, h)));
    __ Ldc1(f6, MemOperand(a0, offsetof(T, i)));
    __ Madd_d(f14, f6, f4, f6, f8);
    __ Sdc1(f14, MemOperand(a0, offsetof(T, h)));
  }

  // Single precision floating point instructions.
  __ Lwc1(f4, MemOperand(a0, offsetof(T, fa)));
  __ Lwc1(f6, MemOperand(a0, offsetof(T, fb)));
  __ add_s(f8, f4, f6);
  __ Swc1(f8, MemOperand(a0, offsetof(T, fc)));  // fc = fa + fb.

  __ neg_s(f10, f6);  // -fb
  __ sub_s(f10, f8, f10);
  __ Swc1(f10, MemOperand(a0, offsetof(T, fd)));  // fd = fc - (-fb).

  __ Swc1(f4, MemOperand(a0, offsetof(T, fb)));  // fb = fa.

  __ li(t0, 120);
  __ mtc1(t0, f14);
  __ cvt_s_w(f14, f14);   // f14 = 120.0.
  __ mul_s(f10, f10, f14);
  __ Swc1(f10, MemOperand(a0, offsetof(T, fe)));  // fe = fd * 120

  __ div_s(f12, f10, f4);
  __ Swc1(f12, MemOperand(a0, offsetof(T, ff)));  // ff = fe / fa

  __ sqrt_s(f14, f12);
  __ Swc1(f14, MemOperand(a0, offsetof(T, fg)));

  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  // Double test values.
  t.a = 1.5e14;
  t.b = 2.75e11;
  t.c = 0.0;
  t.d = 0.0;
  t.e = 0.0;
  t.f = 0.0;
  t.h = 1.5;
  t.i = 2.75;
  // Single test values.
  t.fa = 1.5e6;
  t.fb = 2.75e4;
  t.fc = 0.0;
  t.fd = 0.0;
  t.fe = 0.0;
  t.ff = 0.0;
  f.Call(&t, 0, 0, 0, 0);
  // Expected double results.
  CHECK_EQ(1.5e14, t.a);
  CHECK_EQ(1.5e14, t.b);
  CHECK_EQ(1.50275e14, t.c);
  CHECK_EQ(1.50550e14, t.d);
  CHECK_EQ(1.8066e16, t.e);
  CHECK_EQ(120.44, t.f);
  CHECK_EQ(10.97451593465515908537, t.g);
  if (kArchVariant == kMips64r2) {
    CHECK_EQ(6.875, t.h);
  }
  // Expected single results.
  CHECK_EQ(1.5e6, t.fa);
  CHECK_EQ(1.5e6, t.fb);
  CHECK_EQ(1.5275e06, t.fc);
  CHECK_EQ(1.5550e06, t.fd);
  CHECK_EQ(1.866e08, t.fe);
  CHECK_EQ(124.40000152587890625, t.ff);
  CHECK_EQ(11.1534748077392578125, t.fg);
}


TEST(MIPS4) {
  // Test moves between floating point and integer registers.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    double a;
    double b;
    double c;
    double d;
    int64_t high;
    int64_t low;
  };
  T t;

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  __ Ldc1(f4, MemOperand(a0, offsetof(T, a)));
  __ Ldc1(f5, MemOperand(a0, offsetof(T, b)));

  // Swap f4 and f5, by using 3 integer registers, a4-a6,
  // both two 32-bit chunks, and one 64-bit chunk.
  // mXhc1 is mips32/64-r2 only, not r1,
  // but we will not support r1 in practice.
  __ mfc1(a4, f4);
  __ mfhc1(a5, f4);
  __ dmfc1(a6, f5);

  __ mtc1(a4, f5);
  __ mthc1(a5, f5);
  __ dmtc1(a6, f4);

  // Store the swapped f4 and f5 back to memory.
  __ Sdc1(f4, MemOperand(a0, offsetof(T, a)));
  __ Sdc1(f5, MemOperand(a0, offsetof(T, c)));

  // Test sign extension of move operations from coprocessor.
  __ Ldc1(f4, MemOperand(a0, offsetof(T, d)));
  __ mfhc1(a4, f4);
  __ mfc1(a5, f4);

  __ Sd(a4, MemOperand(a0, offsetof(T, high)));
  __ Sd(a5, MemOperand(a0, offsetof(T, low)));

  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  t.a = 1.5e22;
  t.b = 2.75e11;
  t.c = 17.17;
  t.d = -2.75e11;
  f.Call(&t, 0, 0, 0, 0);

  CHECK_EQ(2.75e11, t.a);
  CHECK_EQ(2.75e11, t.b);
  CHECK_EQ(1.5e22, t.c);
  CHECK_EQ(static_cast<int64_t>(0xFFFFFFFFC25001D1L), t.high);
  CHECK_EQ(static_cast<int64_t>(0xFFFFFFFFBF800000L), t.low);
}


TEST(MIPS5) {
  // Test conversions between doubles and integers.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    double a;
    double b;
    int i;
    int j;
  };
  T t;

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  // Load all structure elements to registers.
  __ Ldc1(f4, MemOperand(a0, offsetof(T, a)));
  __ Ldc1(f6, MemOperand(a0, offsetof(T, b)));
  __ Lw(a4, MemOperand(a0, offsetof(T, i)));
  __ Lw(a5, MemOperand(a0, offsetof(T, j)));

  // Convert double in f4 to int in element i.
  __ cvt_w_d(f8, f4);
  __ mfc1(a6, f8);
  __ Sw(a6, MemOperand(a0, offsetof(T, i)));

  // Convert double in f6 to int in element j.
  __ cvt_w_d(f10, f6);
  __ mfc1(a7, f10);
  __ Sw(a7, MemOperand(a0, offsetof(T, j)));

  // Convert int in original i (a4) to double in a.
  __ mtc1(a4, f12);
  __ cvt_d_w(f0, f12);
  __ Sdc1(f0, MemOperand(a0, offsetof(T, a)));

  // Convert int in original j (a5) to double in b.
  __ mtc1(a5, f14);
  __ cvt_d_w(f2, f14);
  __ Sdc1(f2, MemOperand(a0, offsetof(T, b)));

  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  t.a = 1.5e4;
  t.b = 2.75e8;
  t.i = 12345678;
  t.j = -100000;
  f.Call(&t, 0, 0, 0, 0);

  CHECK_EQ(12345678.0, t.a);
  CHECK_EQ(-100000.0, t.b);
  CHECK_EQ(15000, t.i);
  CHECK_EQ(275000000, t.j);
}


TEST(MIPS6) {
  // Test simple memory loads and stores.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    uint32_t ui;
    int32_t si;
    int32_t r1;
    int32_t r2;
    int32_t r3;
    int32_t r4;
    int32_t r5;
    int32_t r6;
  };
  T t;

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  // Basic word load/store.
  __ Lw(a4, MemOperand(a0, offsetof(T, ui)));
  __ Sw(a4, MemOperand(a0, offsetof(T, r1)));

  // lh with positive data.
  __ Lh(a5, MemOperand(a0, offsetof(T, ui)));
  __ Sw(a5, MemOperand(a0, offsetof(T, r2)));

  // lh with negative data.
  __ Lh(a6, MemOperand(a0, offsetof(T, si)));
  __ Sw(a6, MemOperand(a0, offsetof(T, r3)));

  // lhu with negative data.
  __ Lhu(a7, MemOperand(a0, offsetof(T, si)));
  __ Sw(a7, MemOperand(a0, offsetof(T, r4)));

  // Lb with negative data.
  __ Lb(t0, MemOperand(a0, offsetof(T, si)));
  __ Sw(t0, MemOperand(a0, offsetof(T, r5)));

  // sh writes only 1/2 of word.
  __ lui(t1, 0x3333);
  __ ori(t1, t1, 0x3333);
  __ Sw(t1, MemOperand(a0, offsetof(T, r6)));
  __ Lhu(t1, MemOperand(a0, offsetof(T, si)));
  __ Sh(t1, MemOperand(a0, offsetof(T, r6)));

  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  t.ui = 0x11223344;
  t.si = 0x99AABBCC;
  f.Call(&t, 0, 0, 0, 0);

  CHECK_EQ(static_cast<int32_t>(0x11223344), t.r1);
  if (kArchEndian == kLittle)  {
    CHECK_EQ(static_cast<int32_t>(0x3344), t.r2);
    CHECK_EQ(static_cast<int32_t>(0xFFFFBBCC), t.r3);
    CHECK_EQ(static_cast<int32_t>(0x0000BBCC), t.r4);
    CHECK_EQ(static_cast<int32_t>(0xFFFFFFCC), t.r5);
    CHECK_EQ(static_cast<int32_t>(0x3333BBCC), t.r6);
  } else {
    CHECK_EQ(static_cast<int32_t>(0x1122), t.r2);
    CHECK_EQ(static_cast<int32_t>(0xFFFF99AA), t.r3);
    CHECK_EQ(static_cast<int32_t>(0x000099AA), t.r4);
    CHECK_EQ(static_cast<int32_t>(0xFFFFFF99), t.r5);
    CHECK_EQ(static_cast<int32_t>(0x99AA3333), t.r6);
  }
}


TEST(MIPS7) {
  // Test floating point compare and branch instructions.
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
    int32_t result;
  };
  T t;

  // Create a function that accepts &t, and loads, manipulates, and stores
  // the doubles t.a ... t.f.
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  Label neither_is_nan, less_than, outa_here;

  __ Ldc1(f4, MemOperand(a0, offsetof(T, a)));
  __ Ldc1(f6, MemOperand(a0, offsetof(T, b)));
  if (kArchVariant != kMips64r6) {
    __ c(UN, D, f4, f6);
    __ bc1f(&neither_is_nan);
  } else {
    __ cmp(UN, L, f2, f4, f6);
    __ bc1eqz(&neither_is_nan, f2);
  }
  __ nop();
  __ Sw(zero_reg, MemOperand(a0, offsetof(T, result)));
  __ Branch(&outa_here);

  __ bind(&neither_is_nan);

  if (kArchVariant == kMips64r6) {
    __ cmp(OLT, L, f2, f6, f4);
    __ bc1nez(&less_than, f2);
  } else {
    __ c(OLT, D, f6, f4, 2);
    __ bc1t(&less_than, 2);
  }

  __ nop();
  __ Sw(zero_reg, MemOperand(a0, offsetof(T, result)));
  __ Branch(&outa_here);

  __ bind(&less_than);
  __ Addu(a4, zero_reg, Operand(1));
  __ Sw(a4, MemOperand(a0, offsetof(T, result)));  // Set true.

  // This test-case should have additional tests.

  __ bind(&outa_here);

  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  t.a = 1.5e14;
  t.b = 2.75e11;
  t.c = 2.0;
  t.d = -4.0;
  t.e = 0.0;
  t.f = 0.0;
  t.result = 0;
  f.Call(&t, 0, 0, 0, 0);
  CHECK_EQ(1.5e14, t.a);
  CHECK_EQ(2.75e11, t.b);
  CHECK_EQ(1, t.result);
}


TEST(MIPS8) {
  if (kArchVariant == kMips64r2) {
    // Test ROTR and ROTRV instructions.
    CcTest::InitializeVM();
    Isolate* isolate = CcTest::i_isolate();
    HandleScope scope(isolate);

    struct T {
      int32_t input;
      int32_t result_rotr_4;
      int32_t result_rotr_8;
      int32_t result_rotr_12;
      int32_t result_rotr_16;
      int32_t result_rotr_20;
      int32_t result_rotr_24;
      int32_t result_rotr_28;
      int32_t result_rotrv_4;
      int32_t result_rotrv_8;
      int32_t result_rotrv_12;
      int32_t result_rotrv_16;
      int32_t result_rotrv_20;
      int32_t result_rotrv_24;
      int32_t result_rotrv_28;
    };
    T t;

    MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

    // Basic word load.
    __ Lw(a4, MemOperand(a0, offsetof(T, input)));

    // ROTR instruction (called through the Ror macro).
    __ Ror(a5, a4, 0x0004);
    __ Ror(a6, a4, 0x0008);
    __ Ror(a7, a4, 0x000C);
    __ Ror(t0, a4, 0x0010);
    __ Ror(t1, a4, 0x0014);
    __ Ror(t2, a4, 0x0018);
    __ Ror(t3, a4, 0x001C);

    // Basic word store.
    __ Sw(a5, MemOperand(a0, offsetof(T, result_rotr_4)));
    __ Sw(a6, MemOperand(a0, offsetof(T, result_rotr_8)));
    __ Sw(a7, MemOperand(a0, offsetof(T, result_rotr_12)));
    __ Sw(t0, MemOperand(a0, offsetof(T, result_rotr_16)));
    __ Sw(t1, MemOperand(a0, offsetof(T, result_rotr_20)));
    __ Sw(t2, MemOperand(a0, offsetof(T, result_rotr_24)));
    __ Sw(t3, MemOperand(a0, offsetof(T, result_rotr_28)));

    // ROTRV instruction (called through the Ror macro).
    __ li(t3, 0x0004);
    __ Ror(a5, a4, t3);
    __ li(t3, 0x0008);
    __ Ror(a6, a4, t3);
    __ li(t3, 0x000C);
    __ Ror(a7, a4, t3);
    __ li(t3, 0x0010);
    __ Ror(t0, a4, t3);
    __ li(t3, 0x0014);
    __ Ror(t1, a4, t3);
    __ li(t3, 0x0018);
    __ Ror(t2, a4, t3);
    __ li(t3, 0x001C);
    __ Ror(t3, a4, t3);

    // Basic word store.
    __ Sw(a5, MemOperand(a0, offsetof(T, result_rotrv_4)));
    __ Sw(a6, MemOperand(a0, offsetof(T, result_rotrv_8)));
    __ Sw(a7, MemOperand(a0, offsetof(T, result_rotrv_12)));
    __ Sw(t0, MemOperand(a0, offsetof(T, result_rotrv_16)));
    __ Sw(t1, MemOperand(a0, offsetof(T, result_rotrv_20)));
    __ Sw(t2, MemOperand(a0, offsetof(T, result_rotrv_24)));
    __ Sw(t3, MemOperand(a0, offsetof(T, result_rotrv_28)));

    __ jr(ra);
    __ nop();

    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
    auto f = GeneratedCode<F3>::FromCode(isolate, *code);
    t.input = 0x12345678;
    f.Call(&t, 0x0, 0, 0, 0);
    CHECK_EQ(static_cast<int32_t>(0x81234567), t.result_rotr_4);
    CHECK_EQ(static_cast<int32_t>(0x78123456), t.result_rotr_8);
    CHECK_EQ(static_cast<int32_t>(0x67812345), t.result_rotr_12);
    CHECK_EQ(static_cast<int32_t>(0x56781234), t.result_rotr_16);
    CHECK_EQ(static_cast<int32_t>(0x45678123), t.result_rotr_20);
    CHECK_EQ(static_cast<int32_t>(0x34567812), t.result_rotr_24);
    CHECK_EQ(static_cast<int32_t>(0x23456781), t.result_rotr_28);

    CHECK_EQ(static_cast<int32_t>(0x81234567), t.result_rotrv_4);
    CHECK_EQ(static_cast<int32_t>(0x78123456), t.result_rotrv_8);
    CHECK_EQ(static_cast<int32_t>(0x67812345), t.result_rotrv_12);
    CHECK_EQ(static_cast<int32_t>(0x56781234), t.result_rotrv_16);
    CHECK_EQ(static_cast<int32_t>(0x45678123), t.result_rotrv_20);
    CHECK_EQ(static_cast<int32_t>(0x34567812), t.result_rotrv_24);
    CHECK_EQ(static_cast<int32_t>(0x23456781), t.result_rotrv_28);
  }
}


TEST(MIPS9) {
  // Test BRANCH improvements.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  Label exit, exit2, exit3;

  __ Branch(&exit, ge, a0, Operand(zero_reg));
  __ Branch(&exit2, ge, a0, Operand(0x00001FFF));
  __ Branch(&exit3, ge, a0, Operand(0x0001FFFF));

  __ bind(&exit);
  __ bind(&exit2);
  __ bind(&exit3);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  USE(code);
}


TEST(MIPS10) {
  // Test conversions between doubles and long integers.
  // Test hos the long ints map to FP regs pairs.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    double a;
    double a_converted;
    double b;
    int32_t dbl_mant;
    int32_t dbl_exp;
    int32_t long_hi;
    int32_t long_lo;
    int64_t long_as_int64;
    int32_t b_long_hi;
    int32_t b_long_lo;
    int64_t b_long_as_int64;
  };
  T t;

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  if (kArchVariant == kMips64r2) {
    // Rewritten for FR=1 FPU mode:
    //  -  32 FP regs of 64-bits each, no odd/even pairs.
    //  -  Note that cvt_l_d/cvt_d_l ARE legal in FR=1 mode.
    // Load all structure elements to registers.
    __ Ldc1(f0, MemOperand(a0, offsetof(T, a)));

    // Save the raw bits of the double.
    __ mfc1(a4, f0);
    __ mfhc1(a5, f0);
    __ Sw(a4, MemOperand(a0, offsetof(T, dbl_mant)));
    __ Sw(a5, MemOperand(a0, offsetof(T, dbl_exp)));

    // Convert double in f0 to long, save hi/lo parts.
    __ cvt_l_d(f0, f0);
    __ mfc1(a4, f0);  // f0 LS 32 bits of long.
    __ mfhc1(a5, f0);  // f0 MS 32 bits of long.
    __ Sw(a4, MemOperand(a0, offsetof(T, long_lo)));
    __ Sw(a5, MemOperand(a0, offsetof(T, long_hi)));

    // Combine the high/low ints, convert back to double.
    __ dsll32(a6, a5, 0);  // Move a5 to high bits of a6.
    __ or_(a6, a6, a4);
    __ dmtc1(a6, f1);
    __ cvt_d_l(f1, f1);
    __ Sdc1(f1, MemOperand(a0, offsetof(T, a_converted)));

    // Convert the b long integers to double b.
    __ Lw(a4, MemOperand(a0, offsetof(T, b_long_lo)));
    __ Lw(a5, MemOperand(a0, offsetof(T, b_long_hi)));
    __ mtc1(a4, f8);  // f8 LS 32-bits.
    __ mthc1(a5, f8);  // f8 MS 32-bits.
    __ cvt_d_l(f10, f8);
    __ Sdc1(f10, MemOperand(a0, offsetof(T, b)));

    // Convert double b back to long-int.
    __ Ldc1(f31, MemOperand(a0, offsetof(T, b)));
    __ cvt_l_d(f31, f31);
    __ dmfc1(a7, f31);
    __ Sd(a7, MemOperand(a0, offsetof(T, b_long_as_int64)));

    __ jr(ra);
    __ nop();

    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
    auto f = GeneratedCode<F3>::FromCode(isolate, *code);
    t.a = 2.147483647e9;       // 0x7FFFFFFF -> 0x41DFFFFFFFC00000 as double.
    t.b_long_hi = 0x000000FF;  // 0xFF00FF00FF -> 0x426FE01FE01FE000 as double.
    t.b_long_lo = 0x00FF00FF;
    f.Call(&t, 0, 0, 0, 0);

    CHECK_EQ(static_cast<int32_t>(0x41DFFFFF), t.dbl_exp);
    CHECK_EQ(static_cast<int32_t>(0xFFC00000), t.dbl_mant);
    CHECK_EQ(0, t.long_hi);
    CHECK_EQ(static_cast<int32_t>(0x7FFFFFFF), t.long_lo);
    CHECK_EQ(2.147483647e9, t.a_converted);

    // 0xFF00FF00FF -> 1.095233372415e12.
    CHECK_EQ(1.095233372415e12, t.b);
    CHECK_EQ(static_cast<int64_t>(0xFF00FF00FF), t.b_long_as_int64);
  }
}


TEST(MIPS11) {
  // Do not run test on MIPS64r6, as these instructions are removed.
  if (kArchVariant != kMips64r6) {
    // Test LWL, LWR, SWL and SWR instructions.
    CcTest::InitializeVM();
    Isolate* isolate = CcTest::i_isolate();
    HandleScope scope(isolate);

    struct T {
      int32_t reg_init;
      int32_t mem_init;
      int32_t lwl_0;
      int32_t lwl_1;
      int32_t lwl_2;
      int32_t lwl_3;
      int32_t lwr_0;
      int32_t lwr_1;
      int32_t lwr_2;
      int32_t lwr_3;
      int32_t swl_0;
      int32_t swl_1;
      int32_t swl_2;
      int32_t swl_3;
      int32_t swr_0;
      int32_t swr_1;
      int32_t swr_2;
      int32_t swr_3;
    };
    T t;

    MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

    // Test all combinations of LWL and vAddr.
    __ Lw(a4, MemOperand(a0, offsetof(T, reg_init)));
    __ lwl(a4, MemOperand(a0, offsetof(T, mem_init)));
    __ Sw(a4, MemOperand(a0, offsetof(T, lwl_0)));

    __ Lw(a5, MemOperand(a0, offsetof(T, reg_init)));
    __ lwl(a5, MemOperand(a0, offsetof(T, mem_init) + 1));
    __ Sw(a5, MemOperand(a0, offsetof(T, lwl_1)));

    __ Lw(a6, MemOperand(a0, offsetof(T, reg_init)));
    __ lwl(a6, MemOperand(a0, offsetof(T, mem_init) + 2));
    __ Sw(a6, MemOperand(a0, offsetof(T, lwl_2)));

    __ Lw(a7, MemOperand(a0, offsetof(T, reg_init)));
    __ lwl(a7, MemOperand(a0, offsetof(T, mem_init) + 3));
    __ Sw(a7, MemOperand(a0, offsetof(T, lwl_3)));

    // Test all combinations of LWR and vAddr.
    __ Lw(a4, MemOperand(a0, offsetof(T, reg_init)));
    __ lwr(a4, MemOperand(a0, offsetof(T, mem_init)));
    __ Sw(a4, MemOperand(a0, offsetof(T, lwr_0)));

    __ Lw(a5, MemOperand(a0, offsetof(T, reg_init)));
    __ lwr(a5, MemOperand(a0, offsetof(T, mem_init) + 1));
    __ Sw(a5, MemOperand(a0, offsetof(T, lwr_1)));

    __ Lw(a6, MemOperand(a0, offsetof(T, reg_init)));
    __ lwr(a6, MemOperand(a0, offsetof(T, mem_init) + 2));
    __ Sw(a6, MemOperand(a0, offsetof(T, lwr_2)));

    __ Lw(a7, MemOperand(a0, offsetof(T, reg_init)));
    __ lwr(a7, MemOperand(a0, offsetof(T, mem_init) + 3));
    __ Sw(a7, MemOperand(a0, offsetof(T, lwr_3)));

    // Test all combinations of SWL and vAddr.
    __ Lw(a4, MemOperand(a0, offsetof(T, mem_init)));
    __ Sw(a4, MemOperand(a0, offsetof(T, swl_0)));
    __ Lw(a4, MemOperand(a0, offsetof(T, reg_init)));
    __ swl(a4, MemOperand(a0, offsetof(T, swl_0)));

    __ Lw(a5, MemOperand(a0, offsetof(T, mem_init)));
    __ Sw(a5, MemOperand(a0, offsetof(T, swl_1)));
    __ Lw(a5, MemOperand(a0, offsetof(T, reg_init)));
    __ swl(a5, MemOperand(a0, offsetof(T, swl_1) + 1));

    __ Lw(a6, MemOperand(a0, offsetof(T, mem_init)));
    __ Sw(a6, MemOperand(a0, offsetof(T, swl_2)));
    __ Lw(a6, MemOperand(a0, offsetof(T, reg_init)));
    __ swl(a6, MemOperand(a0, offsetof(T, swl_2) + 2));

    __ Lw(a7, MemOperand(a0, offsetof(T, mem_init)));
    __ Sw(a7, MemOperand(a0, offsetof(T, swl_3)));
    __ Lw(a7, MemOperand(a0, offsetof(T, reg_init)));
    __ swl(a7, MemOperand(a0, offsetof(T, swl_3) + 3));

    // Test all combinations of SWR and vAddr.
    __ Lw(a4, MemOperand(a0, offsetof(T, mem_init)));
    __ Sw(a4, MemOperand(a0, offsetof(T, swr_0)));
    __ Lw(a4, MemOperand(a0, offsetof(T, reg_init)));
    __ swr(a4, MemOperand(a0, offsetof(T, swr_0)));

    __ Lw(a5, MemOperand(a0, offsetof(T, mem_init)));
    __ Sw(a5, MemOperand(a0, offsetof(T, swr_1)));
    __ Lw(a5, MemOperand(a0, offsetof(T, reg_init)));
    __ swr(a5, MemOperand(a0, offsetof(T, swr_1) + 1));

    __ Lw(a6, MemOperand(a0, offsetof(T, mem_init)));
    __ Sw(a6, MemOperand(a0, offsetof(T, swr_2)));
    __ Lw(a6, MemOperand(a0, offsetof(T, reg_init)));
    __ swr(a6, MemOperand(a0, offsetof(T, swr_2) + 2));

    __ Lw(a7, MemOperand(a0, offsetof(T, mem_init)));
    __ Sw(a7, MemOperand(a0, offsetof(T, swr_3)));
    __ Lw(a7, MemOperand(a0, offsetof(T, reg_init)));
    __ swr(a7, MemOperand(a0, offsetof(T, swr_3) + 3));

    __ jr(ra);
    __ nop();

    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
    auto f = GeneratedCode<F3>::FromCode(isolate, *code);
    t.reg_init = 0xAABBCCDD;
    t.mem_init = 0x11223344;

    f.Call(&t, 0, 0, 0, 0);

    if (kArchEndian == kLittle) {
      CHECK_EQ(static_cast<int32_t>(0x44BBCCDD), t.lwl_0);
      CHECK_EQ(static_cast<int32_t>(0x3344CCDD), t.lwl_1);
      CHECK_EQ(static_cast<int32_t>(0x223344DD), t.lwl_2);
      CHECK_EQ(static_cast<int32_t>(0x11223344), t.lwl_3);

      CHECK_EQ(static_cast<int32_t>(0x11223344), t.lwr_0);
      CHECK_EQ(static_cast<int32_t>(0xAA112233), t.lwr_1);
      CHECK_EQ(static_cast<int32_t>(0xAABB1122), t.lwr_2);
      CHECK_EQ(static_cast<int32_t>(0xAABBCC11), t.lwr_3);

      CHECK_EQ(static_cast<int32_t>(0x112233AA), t.swl_0);
      CHECK_EQ(static_cast<int32_t>(0x1122AABB), t.swl_1);
      CHECK_EQ(static_cast<int32_t>(0x11AABBCC), t.swl_2);
      CHECK_EQ(static_cast<int32_t>(0xAABBCCDD), t.swl_3);

      CHECK_EQ(static_cast<int32_t>(0xAABBCCDD), t.swr_0);
      CHECK_EQ(static_cast<int32_t>(0xBBCCDD44), t.swr_1);
      CHECK_EQ(static_cast<int32_t>(0xCCDD3344), t.swr_2);
      CHECK_EQ(static_cast<int32_t>(0xDD223344), t.swr_3);
    } else {
      CHECK_EQ(static_cast<int32_t>(0x11223344), t.lwl_0);
      CHECK_EQ(static_cast<int32_t>(0x223344DD), t.lwl_1);
      CHECK_EQ(static_cast<int32_t>(0x3344CCDD), t.lwl_2);
      CHECK_EQ(static_cast<int32_t>(0x44BBCCDD), t.lwl_3);

      CHECK_EQ(static_cast<int32_t>(0xAABBCC11), t.lwr_0);
      CHECK_EQ(static_cast<int32_t>(0xAABB1122), t.lwr_1);
      CHECK_EQ(static_cast<int32_t>(0xAA112233), t.lwr_2);
      CHECK_EQ(static_cast<int32_t>(0x11223344), t.lwr_3);

      CHECK_EQ(static_cast<int32_t>(0xAABBCCDD), t.swl_0);
      CHECK_EQ(static_cast<int32_t>(0x11AABBCC), t.swl_1);
      CHECK_EQ(static_cast<int32_t>(0x1122AABB), t.swl_2);
      CHECK_EQ(static_cast<int32_t>(0x112233AA), t.swl_3);

      CHECK_EQ(static_cast<int32_t>(0xDD223344), t.swr_0);
      CHECK_EQ(static_cast<int32_t>(0xCCDD3344), t.swr_1);
      CHECK_EQ(static_cast<int32_t>(0xBBCCDD44), t.swr_2);
      CHECK_EQ(static_cast<int32_t>(0xAABBCCDD), t.swr_3);
    }
  }
}


TEST(MIPS12) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    int32_t x;
    int32_t y;
    int32_t y1;
    int32_t y2;
    int32_t y3;
    int32_t y4;
  };
  T t;

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  __ mov(t2, fp);  // Save frame pointer.
  __ mov(fp, a0);  // Access struct T by fp.
  __ Lw(a4, MemOperand(a0, offsetof(T, y)));
  __ Lw(a7, MemOperand(a0, offsetof(T, y4)));

  __ addu(a5, a4, a7);
  __ subu(t0, a4, a7);
  __ nop();
  __ push(a4);  // These instructions disappear after opt.
  __ Pop();
  __ addu(a4, a4, a4);
  __ nop();
  __ Pop();     // These instructions disappear after opt.
  __ push(a7);
  __ nop();
  __ push(a7);  // These instructions disappear after opt.
  __ pop(a7);
  __ nop();
  __ push(a7);
  __ pop(t0);
  __ nop();
  __ Sw(a4, MemOperand(fp, offsetof(T, y)));
  __ Lw(a4, MemOperand(fp, offsetof(T, y)));
  __ nop();
  __ Sw(a4, MemOperand(fp, offsetof(T, y)));
  __ Lw(a5, MemOperand(fp, offsetof(T, y)));
  __ nop();
  __ push(a5);
  __ Lw(a5, MemOperand(fp, offsetof(T, y)));
  __ pop(a5);
  __ nop();
  __ push(a5);
  __ Lw(a6, MemOperand(fp, offsetof(T, y)));
  __ pop(a5);
  __ nop();
  __ push(a5);
  __ Lw(a6, MemOperand(fp, offsetof(T, y)));
  __ pop(a6);
  __ nop();
  __ push(a6);
  __ Lw(a6, MemOperand(fp, offsetof(T, y)));
  __ pop(a5);
  __ nop();
  __ push(a5);
  __ Lw(a6, MemOperand(fp, offsetof(T, y)));
  __ pop(a7);
  __ nop();

  __ mov(fp, t2);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  t.x = 1;
  t.y = 2;
  t.y1 = 3;
  t.y2 = 4;
  t.y3 = 0XBABA;
  t.y4 = 0xDEDA;

  f.Call(&t, 0, 0, 0, 0);

  CHECK_EQ(3, t.y1);
}


TEST(MIPS13) {
  // Test Cvt_d_uw and Trunc_uw_d macros.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    double cvt_big_out;
    double cvt_small_out;
    uint32_t trunc_big_out;
    uint32_t trunc_small_out;
    uint32_t cvt_big_in;
    uint32_t cvt_small_in;
  };
  T t;

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  __ Sw(a4, MemOperand(a0, offsetof(T, cvt_small_in)));
  __ Cvt_d_uw(f10, a4);
  __ Sdc1(f10, MemOperand(a0, offsetof(T, cvt_small_out)));

  __ Trunc_uw_d(f10, f10, f4);
  __ Swc1(f10, MemOperand(a0, offsetof(T, trunc_small_out)));

  __ Sw(a4, MemOperand(a0, offsetof(T, cvt_big_in)));
  __ Cvt_d_uw(f8, a4);
  __ Sdc1(f8, MemOperand(a0, offsetof(T, cvt_big_out)));

  __ Trunc_uw_d(f8, f8, f4);
  __ Swc1(f8, MemOperand(a0, offsetof(T, trunc_big_out)));

  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);

  t.cvt_big_in = 0xFFFFFFFF;
  t.cvt_small_in  = 333;

  f.Call(&t, 0, 0, 0, 0);

  CHECK_EQ(t.cvt_big_out, static_cast<double>(t.cvt_big_in));
  CHECK_EQ(t.cvt_small_out, static_cast<double>(t.cvt_small_in));

  CHECK_EQ(static_cast<int>(t.trunc_big_out), static_cast<int>(t.cvt_big_in));
  CHECK_EQ(static_cast<int>(t.trunc_small_out),
           static_cast<int>(t.cvt_small_in));
}


TEST(MIPS14) {
  // Test round, floor, ceil, trunc, cvt.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

#define ROUND_STRUCT_ELEMENT(x) \
  uint32_t x##_isNaN2008; \
  int32_t x##_up_out; \
  int32_t x##_down_out; \
  int32_t neg_##x##_up_out; \
  int32_t neg_##x##_down_out; \
  uint32_t x##_err1_out; \
  uint32_t x##_err2_out; \
  uint32_t x##_err3_out; \
  uint32_t x##_err4_out; \
  int32_t x##_invalid_result;

  struct T {
    double round_up_in;
    double round_down_in;
    double neg_round_up_in;
    double neg_round_down_in;
    double err1_in;
    double err2_in;
    double err3_in;
    double err4_in;

    ROUND_STRUCT_ELEMENT(round)
    ROUND_STRUCT_ELEMENT(floor)
    ROUND_STRUCT_ELEMENT(ceil)
    ROUND_STRUCT_ELEMENT(trunc)
    ROUND_STRUCT_ELEMENT(cvt)
  };
  T t;

#undef ROUND_STRUCT_ELEMENT

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  // Save FCSR.
  __ cfc1(a1, FCSR);
  // Disable FPU exceptions.
  __ ctc1(zero_reg, FCSR);
#define RUN_ROUND_TEST(x)                                       \
  __ cfc1(t0, FCSR);                                            \
  __ Sw(t0, MemOperand(a0, offsetof(T, x##_isNaN2008)));        \
  __ Ldc1(f0, MemOperand(a0, offsetof(T, round_up_in)));        \
  __ x##_w_d(f0, f0);                                           \
  __ Swc1(f0, MemOperand(a0, offsetof(T, x##_up_out)));         \
                                                                \
  __ Ldc1(f0, MemOperand(a0, offsetof(T, round_down_in)));      \
  __ x##_w_d(f0, f0);                                           \
  __ Swc1(f0, MemOperand(a0, offsetof(T, x##_down_out)));       \
                                                                \
  __ Ldc1(f0, MemOperand(a0, offsetof(T, neg_round_up_in)));    \
  __ x##_w_d(f0, f0);                                           \
  __ Swc1(f0, MemOperand(a0, offsetof(T, neg_##x##_up_out)));   \
                                                                \
  __ Ldc1(f0, MemOperand(a0, offsetof(T, neg_round_down_in)));  \
  __ x##_w_d(f0, f0);                                           \
  __ Swc1(f0, MemOperand(a0, offsetof(T, neg_##x##_down_out))); \
                                                                \
  __ Ldc1(f0, MemOperand(a0, offsetof(T, err1_in)));            \
  __ ctc1(zero_reg, FCSR);                                      \
  __ x##_w_d(f0, f0);                                           \
  __ cfc1(a2, FCSR);                                            \
  __ Sw(a2, MemOperand(a0, offsetof(T, x##_err1_out)));         \
                                                                \
  __ Ldc1(f0, MemOperand(a0, offsetof(T, err2_in)));            \
  __ ctc1(zero_reg, FCSR);                                      \
  __ x##_w_d(f0, f0);                                           \
  __ cfc1(a2, FCSR);                                            \
  __ Sw(a2, MemOperand(a0, offsetof(T, x##_err2_out)));         \
                                                                \
  __ Ldc1(f0, MemOperand(a0, offsetof(T, err3_in)));            \
  __ ctc1(zero_reg, FCSR);                                      \
  __ x##_w_d(f0, f0);                                           \
  __ cfc1(a2, FCSR);                                            \
  __ Sw(a2, MemOperand(a0, offsetof(T, x##_err3_out)));         \
                                                                \
  __ Ldc1(f0, MemOperand(a0, offsetof(T, err4_in)));            \
  __ ctc1(zero_reg, FCSR);                                      \
  __ x##_w_d(f0, f0);                                           \
  __ cfc1(a2, FCSR);                                            \
  __ Sw(a2, MemOperand(a0, offsetof(T, x##_err4_out)));         \
  __ Swc1(f0, MemOperand(a0, offsetof(T, x##_invalid_result)));

  RUN_ROUND_TEST(round)
  RUN_ROUND_TEST(floor)
  RUN_ROUND_TEST(ceil)
  RUN_ROUND_TEST(trunc)
  RUN_ROUND_TEST(cvt)

  // Restore FCSR.
  __ ctc1(a1, FCSR);

  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);

  t.round_up_in = 123.51;
  t.round_down_in = 123.49;
  t.neg_round_up_in = -123.5;
  t.neg_round_down_in = -123.49;
  t.err1_in = 123.51;
  t.err2_in = 1;
  t.err3_in = static_cast<double>(1) + 0xFFFFFFFF;
  t.err4_in = NAN;

  f.Call(&t, 0, 0, 0, 0);

#define GET_FPU_ERR(x) (static_cast<int>(x & kFCSRFlagMask))
#define CHECK_NAN2008(x) (x & kFCSRNaN2008FlagMask)
#define CHECK_ROUND_RESULT(type) \
  CHECK(GET_FPU_ERR(t.type##_err1_out) & kFCSRInexactFlagMask); \
  CHECK_EQ(0, GET_FPU_ERR(t.type##_err2_out)); \
  CHECK(GET_FPU_ERR(t.type##_err3_out) & kFCSRInvalidOpFlagMask); \
  CHECK(GET_FPU_ERR(t.type##_err4_out) & kFCSRInvalidOpFlagMask); \
  if (CHECK_NAN2008(t.type##_isNaN2008) && kArchVariant == kMips64r6) { \
    CHECK_EQ(static_cast<int32_t>(0), t.type##_invalid_result);\
  } else { \
    CHECK_EQ(static_cast<int32_t>(kFPUInvalidResult), t.type##_invalid_result);\
  }

  CHECK_ROUND_RESULT(round);
  CHECK_ROUND_RESULT(floor);
  CHECK_ROUND_RESULT(ceil);
  CHECK_ROUND_RESULT(cvt);
}


TEST(MIPS15) {
  // Test chaining of label usages within instructions (issue 1644).
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  Assembler assm(AssemblerOptions{});

  Label target;
  __ beq(v0, v1, &target);
  __ nop();
  __ bne(v0, v1, &target);
  __ nop();
  __ bind(&target);
  __ nop();
}


// ----- mips64 tests -----------------------------------------------

TEST(MIPS16) {
  // Test 64-bit memory loads and stores.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    int64_t r1;
    int64_t r2;
    int64_t r3;
    int64_t r4;
    int64_t r5;
    int64_t r6;
    int64_t r7;
    int64_t r8;
    int64_t r9;
    int64_t r10;
    int64_t r11;
    int64_t r12;
    uint32_t ui;
    int32_t si;
  };
  T t;

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  // Basic 32-bit word load/store, with un-signed data.
  __ Lw(a4, MemOperand(a0, offsetof(T, ui)));
  __ Sw(a4, MemOperand(a0, offsetof(T, r1)));

  // Check that the data got zero-extended into 64-bit a4.
  __ Sd(a4, MemOperand(a0, offsetof(T, r2)));

  // Basic 32-bit word load/store, with SIGNED data.
  __ Lw(a5, MemOperand(a0, offsetof(T, si)));
  __ Sw(a5, MemOperand(a0, offsetof(T, r3)));

  // Check that the data got sign-extended into 64-bit a4.
  __ Sd(a5, MemOperand(a0, offsetof(T, r4)));

  // 32-bit UNSIGNED word load/store, with SIGNED data.
  __ Lwu(a6, MemOperand(a0, offsetof(T, si)));
  __ Sw(a6, MemOperand(a0, offsetof(T, r5)));

  // Check that the data got zero-extended into 64-bit a4.
  __ Sd(a6, MemOperand(a0, offsetof(T, r6)));

  // lh with positive data.
  __ Lh(a5, MemOperand(a0, offsetof(T, ui)));
  __ Sw(a5, MemOperand(a0, offsetof(T, r7)));

  // lh with negative data.
  __ Lh(a6, MemOperand(a0, offsetof(T, si)));
  __ Sw(a6, MemOperand(a0, offsetof(T, r8)));

  // lhu with negative data.
  __ Lhu(a7, MemOperand(a0, offsetof(T, si)));
  __ Sw(a7, MemOperand(a0, offsetof(T, r9)));

  // Lb with negative data.
  __ Lb(t0, MemOperand(a0, offsetof(T, si)));
  __ Sw(t0, MemOperand(a0, offsetof(T, r10)));

  // sh writes only 1/2 of word.
  __ Lw(a4, MemOperand(a0, offsetof(T, ui)));
  __ Sh(a4, MemOperand(a0, offsetof(T, r11)));
  __ Lw(a4, MemOperand(a0, offsetof(T, si)));
  __ Sh(a4, MemOperand(a0, offsetof(T, r12)));

  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  t.ui = 0x44332211;
  t.si = 0x99AABBCC;
  t.r1 = 0x5555555555555555;
  t.r2 = 0x5555555555555555;
  t.r3 = 0x5555555555555555;
  t.r4 = 0x5555555555555555;
  t.r5 = 0x5555555555555555;
  t.r6 = 0x5555555555555555;
  t.r7 = 0x5555555555555555;
  t.r8 = 0x5555555555555555;
  t.r9 = 0x5555555555555555;
  t.r10 = 0x5555555555555555;
  t.r11 = 0x5555555555555555;
  t.r12 = 0x5555555555555555;

  f.Call(&t, 0, 0, 0, 0);

  if (kArchEndian == kLittle) {
    // Unsigned data, 32 & 64
    CHECK_EQ(static_cast<int64_t>(0x5555555544332211L), t.r1);  // lw, sw.
    CHECK_EQ(static_cast<int64_t>(0x0000000044332211L), t.r2);  // sd.

    // Signed data, 32 & 64.
    CHECK_EQ(static_cast<int64_t>(0x5555555599AABBCCL), t.r3);  // lw, sw.
    CHECK_EQ(static_cast<int64_t>(0xFFFFFFFF99AABBCCL), t.r4);  // sd.

    // Signed data, 32 & 64.
    CHECK_EQ(static_cast<int64_t>(0x5555555599AABBCCL), t.r5);  // lwu, sw.
    CHECK_EQ(static_cast<int64_t>(0x0000000099AABBCCL), t.r6);  // sd.

    // lh with unsigned and signed data.
    CHECK_EQ(static_cast<int64_t>(0x5555555500002211L), t.r7);  // lh, sw.
    CHECK_EQ(static_cast<int64_t>(0x55555555FFFFBBCCL), t.r8);  // lh, sw.

    // lhu with signed data.
    CHECK_EQ(static_cast<int64_t>(0x555555550000BBCCL), t.r9);  // lhu, sw.

    // lb with signed data.
    CHECK_EQ(static_cast<int64_t>(0x55555555FFFFFFCCL), t.r10);  // lb, sw.

    // sh with unsigned and signed data.
    CHECK_EQ(static_cast<int64_t>(0x5555555555552211L), t.r11);  // lw, sh.
    CHECK_EQ(static_cast<int64_t>(0x555555555555BBCCL), t.r12);  // lw, sh.
  } else {
    // Unsigned data, 32 & 64
    CHECK_EQ(static_cast<int64_t>(0x4433221155555555L), t.r1);  // lw, sw.
    CHECK_EQ(static_cast<int64_t>(0x0000000044332211L), t.r2);  // sd.

    // Signed data, 32 & 64.
    CHECK_EQ(static_cast<int64_t>(0x99AABBCC55555555L), t.r3);  // lw, sw.
    CHECK_EQ(static_cast<int64_t>(0xFFFFFFFF99AABBCCL), t.r4);  // sd.

    // Signed data, 32 & 64.
    CHECK_EQ(static_cast<int64_t>(0x99AABBCC55555555L), t.r5);  // lwu, sw.
    CHECK_EQ(static_cast<int64_t>(0x0000000099AABBCCL), t.r6);  // sd.

    // lh with unsigned and signed data.
    CHECK_EQ(static_cast<int64_t>(0x0000443355555555L), t.r7);  // lh, sw.
    CHECK_EQ(static_cast<int64_t>(0xFFFF99AA55555555L), t.r8);  // lh, sw.

    // lhu with signed data.
    CHECK_EQ(static_cast<int64_t>(0x000099AA55555555L), t.r9);  // lhu, sw.

    // lb with signed data.
    CHECK_EQ(static_cast<int64_t>(0xFFFFFF9955555555L), t.r10);  // lb, sw.

    // sh with unsigned and signed data.
    CHECK_EQ(static_cast<int64_t>(0x2211555555555555L), t.r11);  // lw, sh.
    CHECK_EQ(static_cast<int64_t>(0xBBCC555555555555L), t.r12);  // lw, sh.
  }
}


// ----------------------mips64r6 specific tests----------------------
TEST(seleqz_selnez) {
  if (kArchVariant == kMips64r6) {
    CcTest::InitializeVM();
    Isolate* isolate = CcTest::i_isolate();
    HandleScope scope(isolate);
    MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

    struct Test {
      int a;
      int b;
      int c;
      int d;
      double e;
      double f;
      double g;
      double h;
      float i;
      float j;
      float k;
      float l;
    };

    Test test;
    // Integer part of test.
    __ addiu(t1, zero_reg, 1);                      // t1 = 1
    __ seleqz(t3, t1, zero_reg);                    // t3 = 1
    __ Sw(t3, MemOperand(a0, offsetof(Test, a)));   // a = 1
    __ seleqz(t2, t1, t1);                          // t2 = 0
    __ Sw(t2, MemOperand(a0, offsetof(Test, b)));   // b = 0
    __ selnez(t3, t1, zero_reg);                    // t3 = 1;
    __ Sw(t3, MemOperand(a0, offsetof(Test, c)));   // c = 0
    __ selnez(t3, t1, t1);                          // t3 = 1
    __ Sw(t3, MemOperand(a0, offsetof(Test, d)));   // d = 1
    // Floating point part of test.
    __ Ldc1(f0, MemOperand(a0, offsetof(Test, e)));   // src
    __ Ldc1(f2, MemOperand(a0, offsetof(Test, f)));   // test
    __ Lwc1(f8, MemOperand(a0, offsetof(Test, i)));   // src
    __ Lwc1(f10, MemOperand(a0, offsetof(Test, j)));  // test
    __ seleqz_d(f4, f0, f2);
    __ selnez_d(f6, f0, f2);
    __ seleqz_s(f12, f8, f10);
    __ selnez_s(f14, f8, f10);
    __ Sdc1(f4, MemOperand(a0, offsetof(Test, g)));   // src
    __ Sdc1(f6, MemOperand(a0, offsetof(Test, h)));   // src
    __ Swc1(f12, MemOperand(a0, offsetof(Test, k)));  // src
    __ Swc1(f14, MemOperand(a0, offsetof(Test, l)));  // src
    __ jr(ra);
    __ nop();
    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
    auto f = GeneratedCode<F3>::FromCode(isolate, *code);

    f.Call(&test, 0, 0, 0, 0);

    CHECK_EQ(1, test.a);
    CHECK_EQ(0, test.b);
    CHECK_EQ(0, test.c);
    CHECK_EQ(1, test.d);

    const int test_size = 3;
    const int input_size = 5;

    double inputs_D[input_size] = {0.0, 65.2, -70.32,
      18446744073709551621.0, -18446744073709551621.0};
    double outputs_D[input_size] = {0.0, 65.2, -70.32,
      18446744073709551621.0, -18446744073709551621.0};
    double tests_D[test_size*2] = {2.8, 2.9, -2.8, -2.9,
      18446744073709551616.0, 18446744073709555712.0};
    float inputs_S[input_size] = {0.0, 65.2, -70.32,
      18446744073709551621.0, -18446744073709551621.0};
    float outputs_S[input_size] = {0.0, 65.2, -70.32,
      18446744073709551621.0, -18446744073709551621.0};
    float tests_S[test_size*2] = {2.9, 2.8, -2.9, -2.8,
      18446744073709551616.0, 18446746272732807168.0};
    for (int j = 0; j < test_size; j += 2) {
      for (int i=0; i < input_size; i++) {
        test.e = inputs_D[i];
        test.f = tests_D[j];
        test.i = inputs_S[i];
        test.j = tests_S[j];
        f.Call(&test, 0, 0, 0, 0);
        CHECK_EQ(outputs_D[i], test.g);
        CHECK_EQ(0, test.h);
        CHECK_EQ(outputs_S[i], test.k);
        CHECK_EQ(0, test.l);

        test.f = tests_D[j+1];
        test.j = tests_S[j+1];
        f.Call(&test, 0, 0, 0, 0);
        CHECK_EQ(0, test.g);
        CHECK_EQ(outputs_D[i], test.h);
        CHECK_EQ(0, test.k);
        CHECK_EQ(outputs_S[i], test.l);
      }
    }
  }
}



TEST(min_max) {
  if (kArchVariant == kMips64r6) {
    CcTest::InitializeVM();
    Isolate* isolate = CcTest::i_isolate();
    HandleScope scope(isolate);
    MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

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
    const float fminf = std::numeric_limits<float>::infinity();
    const int kTableLength = 13;
    double inputsa[kTableLength] = {2.0,  3.0,  dnan, 3.0,   -0.0, 0.0, dinf,
                                    dnan, 42.0, dinf, dminf, dinf, dnan};
    double inputsb[kTableLength] = {3.0,  2.0,  3.0,  dnan, 0.0,   -0.0, dnan,
                                    dinf, dinf, 42.0, dinf, dminf, dnan};
    double outputsdmin[kTableLength] = {2.0,   2.0,   3.0,  3.0,  -0.0,
                                        -0.0,  dinf,  dinf, 42.0, 42.0,
                                        dminf, dminf, dnan};
    double outputsdmax[kTableLength] = {3.0,  3.0,  3.0,  3.0,  0.0,  0.0, dinf,
                                        dinf, dinf, dinf, dinf, dinf, dnan};

    float inputse[kTableLength] = {2.0,  3.0,  fnan, 3.0,   -0.0, 0.0, finf,
                                   fnan, 42.0, finf, fminf, finf, fnan};
    float inputsf[kTableLength] = {3.0,  2.0,  3.0,  fnan, 0.0,   -0.0, fnan,
                                   finf, finf, 42.0, finf, fminf, fnan};
    float outputsfmin[kTableLength] = {2.0,   2.0,   3.0,  3.0,  -0.0,
                                       -0.0,  finf,  finf, 42.0, 42.0,
                                       fminf, fminf, fnan};
    float outputsfmax[kTableLength] = {3.0,  3.0,  3.0,  3.0,  0.0,  0.0, finf,
                                       finf, finf, finf, finf, finf, fnan};

    __ Ldc1(f4, MemOperand(a0, offsetof(TestFloat, a)));
    __ Ldc1(f8, MemOperand(a0, offsetof(TestFloat, b)));
    __ Lwc1(f2, MemOperand(a0, offsetof(TestFloat, e)));
    __ Lwc1(f6, MemOperand(a0, offsetof(TestFloat, f)));
    __ min_d(f10, f4, f8);
    __ max_d(f12, f4, f8);
    __ min_s(f14, f2, f6);
    __ max_s(f16, f2, f6);
    __ Sdc1(f10, MemOperand(a0, offsetof(TestFloat, c)));
    __ Sdc1(f12, MemOperand(a0, offsetof(TestFloat, d)));
    __ Swc1(f14, MemOperand(a0, offsetof(TestFloat, g)));
    __ Swc1(f16, MemOperand(a0, offsetof(TestFloat, h)));
    __ jr(ra);
    __ nop();

    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
    auto f = GeneratedCode<F3>::FromCode(isolate, *code);
    for (int i = 4; i < kTableLength; i++) {
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
}


TEST(rint_d)  {
  if (kArchVariant == kMips64r6) {
    const int kTableLength = 30;
    CcTest::InitializeVM();
    Isolate* isolate = CcTest::i_isolate();
    HandleScope scope(isolate);
    MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

    struct TestFloat {
      double a;
      double b;
      int fcsr;
    };

    TestFloat test;
    double inputs[kTableLength] = {18446744073709551617.0,
      4503599627370496.0, -4503599627370496.0,
      1.26782468584154733584017312973E30, 1.44860108245951772690707170478E147,
      1.7976931348623157E+308, 6.27463370218383111104242366943E-307,
      309485009821345068724781056.89,
      2.1, 2.6, 2.5, 3.1, 3.6, 3.5,
      -2.1, -2.6, -2.5, -3.1, -3.6, -3.5,
      37778931862957161709568.0, 37778931862957161709569.0,
      37778931862957161709580.0, 37778931862957161709581.0,
      37778931862957161709582.0, 37778931862957161709583.0,
      37778931862957161709584.0, 37778931862957161709585.0,
      37778931862957161709586.0, 37778931862957161709587.0};
    double outputs_RN[kTableLength] = {18446744073709551617.0,
      4503599627370496.0, -4503599627370496.0,
      1.26782468584154733584017312973E30, 1.44860108245951772690707170478E147,
      1.7976931348623157E308, 0,
      309485009821345068724781057.0,
      2.0, 3.0, 2.0, 3.0, 4.0, 4.0,
      -2.0, -3.0, -2.0, -3.0, -4.0, -4.0,
      37778931862957161709568.0, 37778931862957161709569.0,
      37778931862957161709580.0, 37778931862957161709581.0,
      37778931862957161709582.0, 37778931862957161709583.0,
      37778931862957161709584.0, 37778931862957161709585.0,
      37778931862957161709586.0, 37778931862957161709587.0};
    double outputs_RZ[kTableLength] = {18446744073709551617.0,
      4503599627370496.0, -4503599627370496.0,
      1.26782468584154733584017312973E30, 1.44860108245951772690707170478E147,
      1.7976931348623157E308, 0,
      309485009821345068724781057.0,
      2.0, 2.0, 2.0, 3.0, 3.0, 3.0,
      -2.0, -2.0, -2.0, -3.0, -3.0, -3.0,
      37778931862957161709568.0, 37778931862957161709569.0,
      37778931862957161709580.0, 37778931862957161709581.0,
      37778931862957161709582.0, 37778931862957161709583.0,
      37778931862957161709584.0, 37778931862957161709585.0,
      37778931862957161709586.0, 37778931862957161709587.0};
    double outputs_RP[kTableLength] = {18446744073709551617.0,
      4503599627370496.0, -4503599627370496.0,
      1.26782468584154733584017312973E30, 1.44860108245951772690707170478E147,
      1.7976931348623157E308, 1,
      309485009821345068724781057.0,
      3.0, 3.0, 3.0, 4.0, 4.0, 4.0,
      -2.0, -2.0, -2.0, -3.0, -3.0, -3.0,
      37778931862957161709568.0, 37778931862957161709569.0,
      37778931862957161709580.0, 37778931862957161709581.0,
      37778931862957161709582.0, 37778931862957161709583.0,
      37778931862957161709584.0, 37778931862957161709585.0,
      37778931862957161709586.0, 37778931862957161709587.0};
    double outputs_RM[kTableLength] = {18446744073709551617.0,
      4503599627370496.0, -4503599627370496.0,
      1.26782468584154733584017312973E30, 1.44860108245951772690707170478E147,
      1.7976931348623157E308, 0,
      309485009821345068724781057.0,
      2.0, 2.0, 2.0, 3.0, 3.0, 3.0,
      -3.0, -3.0, -3.0, -4.0, -4.0, -4.0,
      37778931862957161709568.0, 37778931862957161709569.0,
      37778931862957161709580.0, 37778931862957161709581.0,
      37778931862957161709582.0, 37778931862957161709583.0,
      37778931862957161709584.0, 37778931862957161709585.0,
      37778931862957161709586.0, 37778931862957161709587.0};
    int fcsr_inputs[4] =
      {kRoundToNearest, kRoundToZero, kRoundToPlusInf, kRoundToMinusInf};
    double* outputs[4] = {outputs_RN, outputs_RZ, outputs_RP, outputs_RM};
    __ Ldc1(f4, MemOperand(a0, offsetof(TestFloat, a)));
    __ Lw(t0, MemOperand(a0, offsetof(TestFloat, fcsr)));
    __ ctc1(t0, FCSR);
    __ rint_d(f8, f4);
    __ Sdc1(f8, MemOperand(a0, offsetof(TestFloat, b)));
    __ jr(ra);
    __ nop();

    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
    auto f = GeneratedCode<F3>::FromCode(isolate, *code);

    for (int j = 0; j < 4; j++) {
      test.fcsr = fcsr_inputs[j];
      for (int i = 0; i < kTableLength; i++) {
        test.a = inputs[i];
        f.Call(&test, 0, 0, 0, 0);
        CHECK_EQ(test.b, outputs[j][i]);
      }
    }
  }
}


TEST(sel) {
  if (kArchVariant == kMips64r6) {
    CcTest::InitializeVM();
    Isolate* isolate = CcTest::i_isolate();
    HandleScope scope(isolate);
    MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

    struct Test {
      double dd;
      double ds;
      double dt;
      float fd;
      float fs;
      float ft;
    };

    Test test;
    __ Ldc1(f0, MemOperand(a0, offsetof(Test, dd)));   // test
    __ Ldc1(f2, MemOperand(a0, offsetof(Test, ds)));   // src1
    __ Ldc1(f4, MemOperand(a0, offsetof(Test, dt)));   // src2
    __ Lwc1(f6, MemOperand(a0, offsetof(Test, fd)));   // test
    __ Lwc1(f8, MemOperand(a0, offsetof(Test, fs)));   // src1
    __ Lwc1(f10, MemOperand(a0, offsetof(Test, ft)));  // src2
    __ sel_d(f0, f2, f4);
    __ sel_s(f6, f8, f10);
    __ Sdc1(f0, MemOperand(a0, offsetof(Test, dd)));
    __ Swc1(f6, MemOperand(a0, offsetof(Test, fd)));
    __ jr(ra);
    __ nop();
    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
    auto f = GeneratedCode<F3>::FromCode(isolate, *code);

    const int test_size = 3;
    const int input_size = 5;

    double inputs_dt[input_size] = {0.0, 65.2, -70.32,
      18446744073709551621.0, -18446744073709551621.0};
    double inputs_ds[input_size] = {0.1, 69.88, -91.325,
      18446744073709551625.0, -18446744073709551625.0};
    float inputs_ft[input_size] = {0.0, 65.2, -70.32,
      18446744073709551621.0, -18446744073709551621.0};
    float inputs_fs[input_size] = {0.1, 69.88, -91.325,
      18446744073709551625.0, -18446744073709551625.0};
    double tests_D[test_size*2] = {2.8, 2.9, -2.8, -2.9,
      18446744073709551616.0, 18446744073709555712.0};
    float tests_S[test_size*2] = {2.9, 2.8, -2.9, -2.8,
      18446744073709551616.0, 18446746272732807168.0};
    for (int j = 0; j < test_size; j += 2) {
      for (int i=0; i < input_size; i++) {
        test.dt = inputs_dt[i];
        test.dd = tests_D[j];
        test.ds = inputs_ds[i];
        test.ft = inputs_ft[i];
        test.fd = tests_S[j];
        test.fs = inputs_fs[i];
        f.Call(&test, 0, 0, 0, 0);
        CHECK_EQ(test.dd, inputs_ds[i]);
        CHECK_EQ(test.fd, inputs_fs[i]);

        test.dd = tests_D[j+1];
        test.fd = tests_S[j+1];
        f.Call(&test, 0, 0, 0, 0);
        CHECK_EQ(test.dd, inputs_dt[i]);
        CHECK_EQ(test.fd, inputs_ft[i]);
      }
    }
  }
}


TEST(rint_s)  {
  if (kArchVariant == kMips64r6) {
    const int kTableLength = 30;
    CcTest::InitializeVM();
    Isolate* isolate = CcTest::i_isolate();
    HandleScope scope(isolate);
    MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

    struct TestFloat {
      float a;
      float b;
      int fcsr;
    };

    TestFloat test;
    float inputs[kTableLength] = {18446744073709551617.0,
      4503599627370496.0, -4503599627370496.0,
      1.26782468584154733584017312973E30, 1.44860108245951772690707170478E37,
      1.7976931348623157E+38, 6.27463370218383111104242366943E-37,
      309485009821345068724781056.89,
      2.1, 2.6, 2.5, 3.1, 3.6, 3.5,
      -2.1, -2.6, -2.5, -3.1, -3.6, -3.5,
      37778931862957161709568.0, 37778931862957161709569.0,
      37778931862957161709580.0, 37778931862957161709581.0,
      37778931862957161709582.0, 37778931862957161709583.0,
      37778931862957161709584.0, 37778931862957161709585.0,
      37778931862957161709586.0, 37778931862957161709587.0};
    float outputs_RN[kTableLength] = {18446744073709551617.0,
      4503599627370496.0, -4503599627370496.0,
      1.26782468584154733584017312973E30, 1.44860108245951772690707170478E37,
      1.7976931348623157E38, 0,
      309485009821345068724781057.0,
      2.0, 3.0, 2.0, 3.0, 4.0, 4.0,
      -2.0, -3.0, -2.0, -3.0, -4.0, -4.0,
      37778931862957161709568.0, 37778931862957161709569.0,
      37778931862957161709580.0, 37778931862957161709581.0,
      37778931862957161709582.0, 37778931862957161709583.0,
      37778931862957161709584.0, 37778931862957161709585.0,
      37778931862957161709586.0, 37778931862957161709587.0};
    float outputs_RZ[kTableLength] = {18446744073709551617.0,
      4503599627370496.0, -4503599627370496.0,
      1.26782468584154733584017312973E30, 1.44860108245951772690707170478E37,
      1.7976931348623157E38, 0,
      309485009821345068724781057.0,
      2.0, 2.0, 2.0, 3.0, 3.0, 3.0,
      -2.0, -2.0, -2.0, -3.0, -3.0, -3.0,
      37778931862957161709568.0, 37778931862957161709569.0,
      37778931862957161709580.0, 37778931862957161709581.0,
      37778931862957161709582.0, 37778931862957161709583.0,
      37778931862957161709584.0, 37778931862957161709585.0,
      37778931862957161709586.0, 37778931862957161709587.0};
    float outputs_RP[kTableLength] = {18446744073709551617.0,
      4503599627370496.0, -4503599627370496.0,
      1.26782468584154733584017312973E30, 1.44860108245951772690707170478E37,
      1.7976931348623157E38, 1,
      309485009821345068724781057.0,
      3.0, 3.0, 3.0, 4.0, 4.0, 4.0,
      -2.0, -2.0, -2.0, -3.0, -3.0, -3.0,
      37778931862957161709568.0, 37778931862957161709569.0,
      37778931862957161709580.0, 37778931862957161709581.0,
      37778931862957161709582.0, 37778931862957161709583.0,
      37778931862957161709584.0, 37778931862957161709585.0,
      37778931862957161709586.0, 37778931862957161709587.0};
    float outputs_RM[kTableLength] = {18446744073709551617.0,
      4503599627370496.0, -4503599627370496.0,
      1.26782468584154733584017312973E30, 1.44860108245951772690707170478E37,
      1.7976931348623157E38, 0,
      309485009821345068724781057.0,
      2.0, 2.0, 2.0, 3.0, 3.0, 3.0,
      -3.0, -3.0, -3.0, -4.0, -4.0, -4.0,
      37778931862957161709568.0, 37778931862957161709569.0,
      37778931862957161709580.0, 37778931862957161709581.0,
      37778931862957161709582.0, 37778931862957161709583.0,
      37778931862957161709584.0, 37778931862957161709585.0,
      37778931862957161709586.0, 37778931862957161709587.0};
    int fcsr_inputs[4] =
      {kRoundToNearest, kRoundToZero, kRoundToPlusInf, kRoundToMinusInf};
    float* outputs[4] = {outputs_RN, outputs_RZ, outputs_RP, outputs_RM};
    __ Lwc1(f4, MemOperand(a0, offsetof(TestFloat, a)));
    __ Lw(t0, MemOperand(a0, offsetof(TestFloat, fcsr)));
    __ cfc1(t1, FCSR);
    __ ctc1(t0, FCSR);
    __ rint_s(f8, f4);
    __ Swc1(f8, MemOperand(a0, offsetof(TestFloat, b)));
    __ ctc1(t1, FCSR);
    __ jr(ra);
    __ nop();

    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
    auto f = GeneratedCode<F3>::FromCode(isolate, *code);

    for (int j = 0; j < 4; j++) {
      test.fcsr = fcsr_inputs[j];
      for (int i = 0; i < kTableLength; i++) {
        test.a = inputs[i];
        f.Call(&test, 0, 0, 0, 0);
        CHECK_EQ(test.b, outputs[j][i]);
      }
    }
  }
}


TEST(mina_maxa) {
  if (kArchVariant == kMips64r6) {
    const int kTableLength = 23;
    CcTest::InitializeVM();
    Isolate* isolate = CcTest::i_isolate();
    HandleScope scope(isolate);
    MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
    const double dnan = std::numeric_limits<double>::quiet_NaN();
    const double dinf = std::numeric_limits<double>::infinity();
    const double dminf = -std::numeric_limits<double>::infinity();
    const float fnan = std::numeric_limits<float>::quiet_NaN();
    const float finf = std::numeric_limits<float>::infinity();
    const float fminf = std::numeric_limits<float>::infinity();

    struct TestFloat {
      double a;
      double b;
      double resd;
      double resd1;
      float c;
      float d;
      float resf;
      float resf1;
    };

    TestFloat test;
    double inputsa[kTableLength] = {
        5.3,  4.8, 6.1,  9.8, 9.8,  9.8,  -10.0, -8.9, -9.8,  -10.0, -8.9, -9.8,
        dnan, 3.0, -0.0, 0.0, dinf, dnan, 42.0,  dinf, dminf, dinf,  dnan};
    doub
"""


```