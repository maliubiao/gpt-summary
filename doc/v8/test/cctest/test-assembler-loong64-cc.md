Response:
The user is asking for a summary of the functionality of the provided C++ code snippet. The code is located in `v8/test/cctest/test-assembler-loong64.cc`, suggesting it's a test file for the LoongArch 64-bit assembler within the V8 JavaScript engine.

Here's a breakdown of the thought process to analyze the code:

1. **Identify the core purpose:** The file name and the `#include` directives (`assembler-inl.h`, `macro-assembler.h`) strongly indicate that this code tests the assembler for the LoongArch64 architecture.

2. **Look for test structures:** The presence of `TEST(...)` macros confirms that this is a unit test file using the V8 testing framework (`cctest`). Each `TEST` block likely focuses on testing a specific set of assembler instructions or functionalities.

3. **Examine the `TEST` blocks:** Go through each `TEST` block and understand what it's doing:
    * **Initialization:** Each test starts with `CcTest::InitializeVM()` and sets up the necessary V8 environment (`Isolate`, `HandleScope`, `MacroAssembler`).
    * **Assembler usage:** Inside each test, `MacroAssembler assm(...)` is used to create an assembler object. The code then uses `__` (which is `#define __ assm.`) to emit LoongArch64 assembly instructions.
    * **Instruction patterns:**  Observe the types of instructions being tested (e.g., `addi_d`, `or_`, `lu12i_w`, `add_w`, `mul_w`, `Ld_b`, `St_d`, `sll_w`, etc.). These provide clues about the functionalities being verified.
    * **Code execution:** The `assm.GetCode(...)` and `GeneratedCode<F*>::FromCode(...)` lines compile the generated assembly code into an executable function.
    * **Verification:**  The `f.Call(...)` line executes the generated code. The `CHECK_EQ(...)` lines compare the result of the execution with expected values, validating the correctness of the assembled instructions.

4. **Categorize the tests:**  Group the tests based on the types of instructions or functionalities they cover. For example:
    * Basic arithmetic operations (addition, subtraction).
    * Logical operations (OR).
    * Immediate value loading.
    * Conditional branching.
    * 32-bit arithmetic operations.
    * 64-bit arithmetic operations.
    * Comparison instructions.
    * Bitwise logical operations.
    * Load and store instructions (with immediate offsets and register offsets).
    * Pointer load and store.
    * Shift instructions (32-bit and 64-bit).

5. **Infer the overall functionality:** Based on the individual tests, conclude that the file's primary purpose is to test the correctness of the LoongArch64 assembler implementation in V8. It verifies that different instructions are encoded and executed as expected.

6. **Address specific constraints:**
    * **`.tq` extension:** The prompt asks what it would mean if the file ended in `.tq`. Knowing V8's build system, `.tq` files are for Torque, a TypeScript-like language used for generating C++ code, particularly for built-in functions. Since this file ends in `.cc`, it's a regular C++ file, not a Torque file.
    * **Relationship to JavaScript:**  Assembler code directly relates to how JavaScript code is compiled and executed at a low level. While this specific test file doesn't execute JavaScript *code*, it verifies the foundation upon which JavaScript execution relies.
    * **JavaScript examples:**  Since the tests are about low-level assembler instructions, the JavaScript equivalents would be the operations that eventually get compiled down to these instructions (e.g., `+`, `-`, `|`, `&`, `<<`, `>>`, variable assignments).
    * **Code logic and assumptions:** Each `TEST` block has its own specific logic. The assumptions are the initial register values and the expected outcome after executing the sequence of assembly instructions.
    * **Common programming errors:**  The tests implicitly cover common assembly programming errors like incorrect operand selection, wrong instruction usage, or failing to account for register sizes and sign extension.

7. **Synthesize the summary:** Combine the findings into a concise summary that addresses the user's request. Highlight the main function (testing the assembler), the target architecture (LoongArch64), and the types of instructions being tested.

By following these steps, one can effectively analyze the provided C++ code and generate the desired summary.
这是一个V8源代码文件，位于 `v8/test/cctest/` 目录下，并且名为 `test-assembler-loong64.cc`。 从文件名可以推断，这个文件的主要功能是**测试 V8 引擎中用于 LoongArch 64 位架构的汇编器 (assembler) 的正确性**。

以下是更详细的功能分解：

1. **汇编指令测试:**  该文件包含了一系列独立的测试用例（以 `TEST(...)` 宏定义），每个测试用例都旨在验证特定的一条或一组 LoongArch64 汇编指令的行为是否符合预期。

2. **指令覆盖:**  从代码中可以看出，测试覆盖了多种类型的 LoongArch64 指令，包括：
    * **算术运算指令:**  例如 `add_d`, `addi_d`, `sub_w`, `mul_w`, `div_w`, `mod_w` 等，以及它们的 64 位版本。
    * **逻辑运算指令:**  例如 `or_`, `and_`, `xor_`, `nor_`, `andi_`, `xori_` 等。
    * **位移指令:**  例如 `sll_w`, `srl_w`, `sra_w`, `rotr_w`, 以及它们的立即数版本。
    * **加载和存储指令:**  例如 `Ld_b`, `Ld_h`, `Ld_w`, `Ld_d`, `St_b`, `St_h`, `St_w`，以及带寄存器偏移的版本 `Ld_b(..., MemOperand(a0, a2))`。
    * **立即数加载指令:** 例如 `li`, `lu12i_w`, `lu32i_d`, `lu52i_d`.
    * **比较指令:** 例如 `slt`, `sltu`, `slti`, `sltui`.
    * **分支指令:** 例如 `b` (无条件跳转), `Branch` (条件跳转), `jirl` (跳转到寄存器地址).
    * **指针操作指令:** 例如 `ldptr_w`, `stptr_d`, `stptr_w`.

3. **测试框架集成:**  该文件使用了 V8 的测试框架 `cctest`，通过 `CcTest::InitializeVM()` 初始化 V8 虚拟机环境，并使用 `CHECK_EQ` 宏来断言执行结果是否与预期一致。

4. **代码生成和执行:**  每个测试用例都创建一个 `MacroAssembler` 对象，然后使用宏 `__` 来生成 LoongArch64 汇编代码。 生成的代码会被编译成可执行的机器码，并通过 `GeneratedCode` 执行。

5. **功能验证:**  测试用例通过设置特定的输入值（例如，寄存器值或内存中的数据），执行生成的汇编代码，并检查输出结果（例如，寄存器中的值或内存中的数据）是否与预期的结果相符，从而验证汇编指令的功能是否正确。

**关于您提出的其他问题：**

* **`.tq` 结尾:** 如果 `v8/test/cctest/test-assembler-loong64.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。Torque 是一种用于定义 V8 内部运行时函数的领域特定语言，它会被编译成 C++ 代码。

* **与 JavaScript 的关系:**  `test-assembler-loong64.cc` 中的汇编代码测试直接关系到 **V8 如何将 JavaScript 代码编译成机器码并在 LoongArch64 架构上执行**。JavaScript 的各种操作（如算术运算、逻辑运算、变量赋值等）最终会被 V8 的编译器转换成底层的汇编指令。这个测试文件确保了这些底层的汇编指令在 LoongArch64 上的实现是正确的。

* **JavaScript 举例:** 例如，`TEST(LA0)` 测试了 `addi_d` 指令的加法运算。在 JavaScript 中，这可能对应于简单的加法操作：
   ```javascript
   function testAdd(a) {
     return a + 12; // 0xC 的十六进制表示是 12
   }

   // 假设 V8 编译 `a + 12` 时使用了 addi_d 指令
   ```

* **代码逻辑推理、假设输入与输出:**
    * **以 `TEST(LA1)` 为例:**
        * **假设输入:**  `f.Call(50, 0, 0, 0, 0)`，表示初始时寄存器 `a0` 的值为 50。
        * **代码逻辑:** 该测试用例实现了一个简单的循环，将 `a0` 的值（初始为 50）递减，并累加到 `a2` 中。循环执行直到 `a1` 变为 0。
        * **预期输出:** 累加的结果应该是 50 + 49 + ... + 1 = 1275。 `CHECK_EQ(1275L, res)` 验证了这一点。

* **用户常见的编程错误:**  虽然这个文件是测试汇编器的，但它也间接反映了一些与底层操作相关的常见编程错误，例如：
    * **整数溢出:** 在 `TEST(LA4)` 中，`add_d(a3, a6, a7)` 的结果可能会溢出，测试用例通过检查结果来验证指令在溢出时的行为。在 JavaScript 中，虽然数字类型能表示较大的范围，但底层的汇编指令仍然可能涉及溢出问题。
    * **有符号和无符号数的处理:**  测试用例中使用了 `slt` (有符号小于) 和 `sltu` (无符号小于) 等指令，区分有符号和无符号数的比较是底层编程中常见的需要注意的地方。JavaScript 中虽然不显式区分，但在位运算等场景下，其底层的表示和运算会受到影响。
    * **位运算的错误使用:**  `TEST(LA8)` 测试了位移操作，常见的错误包括位移量超出范围、对有符号数进行逻辑右移（应该使用算术右移）等。

**总结 `test-assembler-loong64.cc` 的功能（第 1 部分）：**

`test-assembler-loong64.cc` 的主要功能是 **作为 V8 JavaScript 引擎针对 LoongArch 64 位架构汇编器的单元测试集的第一部分**。它包含了多个独立的测试用例，用于验证各种 LoongArch64 汇编指令（包括算术、逻辑、位移、加载/存储、比较、分支和指针操作指令）的实现是否正确。这些测试通过生成、执行汇编代码并断言其结果来实现验证。该文件是确保 V8 引擎在 LoongArch64 架构上正确执行 JavaScript 代码的基础。

### 提示词
```
这是目录为v8/test/cctest/test-assembler-loong64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-loong64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
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
// TODO(LOONG64): Refine these signatures per test case.
using F1 = void*(int x, int p1, int p2, int p3, int p4);
using F2 = void*(int x, int y, int p2, int p3, int p4);
using F3 = void*(void* p, int p1, int p2, int p3, int p4);
using F4 = void*(int64_t x, int64_t y, int64_t p2, int64_t p3, int64_t p4);
using F5 = void*(void* p0, void* p1, int p2, int p3, int p4);

#define __ assm.
// v0->a2, v1->a3
TEST(LA0) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  // Addition.
  __ addi_d(a2, a0, 0xC);

  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  int64_t res = reinterpret_cast<int64_t>(f.Call(0xAB0, 0, 0, 0, 0));
  CHECK_EQ(0xABCL, res);
}

TEST(LA1) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  Label L, C;

  __ ori(a1, a0, 0);
  __ ori(a2, zero_reg, 0);
  __ b(&C);

  __ bind(&L);
  __ add_d(a2, a2, a1);
  __ addi_d(a1, a1, -1);

  __ bind(&C);
  __ ori(a3, a1, 0);

  __ Branch(&L, ne, a3, Operand((int64_t)0));

  __ or_(a0, a2, zero_reg);
  __ or_(a1, a3, zero_reg);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F1>::FromCode(isolate, *code);
  int64_t res = reinterpret_cast<int64_t>(f.Call(50, 0, 0, 0, 0));
  CHECK_EQ(1275L, res);
}

TEST(LA2) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label exit, error;

  __ ori(a4, zero_reg, 0);  // 00000000
  __ lu12i_w(a4, 0x12345);  // 12345000
  __ ori(a4, a4, 0);        // 12345000
  __ ori(a2, a4, 0xF0F);    // 12345F0F
  __ Branch(&error, ne, a2, Operand(0x12345F0F));

  __ ori(a4, zero_reg, 0);
  __ lu32i_d(a4, 0x12345);  // 1 2345 0000 0000
  __ ori(a4, a4, 0xFFF);    // 1 2345 0000 0FFF
  __ addi_d(a2, a4, 1);
  __ Branch(&error, ne, a2, Operand(0x1234500001000));

  __ ori(a4, zero_reg, 0);
  __ lu52i_d(a4, zero_reg, 0x123);  // 1230 0000 0000 0000
  __ ori(a4, a4, 0xFFF);            // 123F 0000 0000 0FFF
  __ addi_d(a2, a4, 1);             // 1230 0000 0000 1000
  __ Branch(&error, ne, a2, Operand(0x1230000000001000));

  __ li(a2, 0x31415926);
  __ b(&exit);

  __ bind(&error);
  __ li(a2, 0x666);

  __ bind(&exit);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  int64_t res = reinterpret_cast<int64_t>(f.Call(0, 0, 0, 0, 0));

  CHECK_EQ(0x31415926L, res);
}

TEST(LA3) {
  // Test 32bit calculate instructions.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label exit, error;

  __ li(a4, 0x00000004);
  __ li(a5, 0x00001234);
  __ li(a6, 0x12345678);
  __ li(a7, 0x7FFFFFFF);
  __ li(t0, static_cast<int32_t>(0xFFFFFFFC));
  __ li(t1, static_cast<int32_t>(0xFFFFEDCC));
  __ li(t2, static_cast<int32_t>(0xEDCBA988));
  __ li(t3, static_cast<int32_t>(0x80000000));

  __ ori(a2, zero_reg, 0);  // 0x00000000
  __ add_w(a2, a4, a5);     // 0x00001238
  __ sub_w(a2, a2, a4);     // 0x00001234
  __ Branch(&error, ne, a2, Operand(0x00001234));
  __ ori(a3, zero_reg, 0);  // 0x00000000
  __ add_w(a3, a7, a4);  // 32bit addu result is sign-extended into 64bit reg.
  __ Branch(&error, ne, a3, Operand(0xFFFFFFFF80000003));

  __ sub_w(a3, t3, a4);  // 0x7FFFFFFC
  __ Branch(&error, ne, a3, Operand(0x7FFFFFFC));

  __ ori(a2, zero_reg, 0);         // 0x00000000
  __ ori(a3, zero_reg, 0);         // 0x00000000
  __ addi_w(a2, zero_reg, 0x421);  // 0x00007421
  __ addi_w(a2, a2, -0x1);         // 0x00007420
  __ addi_w(a2, a2, -0x20);        // 0x00007400
  __ Branch(&error, ne, a2, Operand(0x0000400));
  __ addi_w(a3, a7, 0x1);  // 0x80000000 - result is sign-extended.
  __ Branch(&error, ne, a3, Operand(0xFFFFFFFF80000000));

  __ ori(a2, zero_reg, 0);   // 0x00000000
  __ ori(a3, zero_reg, 0);   // 0x00000000
  __ alsl_w(a2, a6, a4, 3);  // 0xFFFFFFFF91A2B3C4
  __ alsl_w(a2, a2, a4, 2);  // 0x468ACF14
  __ Branch(&error, ne, a2, Operand(0x468acf14));
  __ ori(a0, zero_reg, 31);
  __ alsl_wu(a3, a6, a4, 3);  // 0x91A2B3C4
  __ alsl_wu(a3, a3, a7, 1);  // 0xFFFFFFFFA3456787
  __ Branch(&error, ne, a3, Operand(0xA3456787));

  __ ori(a2, zero_reg, 0);
  __ ori(a3, zero_reg, 0);
  __ mul_w(a2, a5, a7);
  __ div_w(a2, a2, a4);
  __ Branch(&error, ne, a2, Operand(0xFFFFFFFFFFFFFB73));
  __ mul_w(a3, a4, t1);
  __ Branch(&error, ne, a3, Operand(0xFFFFFFFFFFFFB730));
  __ div_w(a3, t3, a4);
  __ Branch(&error, ne, a3, Operand(0xFFFFFFFFE0000000));

  __ ori(a2, zero_reg, 0);
  __ mulh_w(a2, a4, t1);
  __ Branch(&error, ne, a2, Operand(0xFFFFFFFFFFFFFFFF));
  __ mulh_w(a2, a4, a6);
  __ Branch(&error, ne, a2, Operand(static_cast<int64_t>(0)));

  __ ori(a2, zero_reg, 0);
  __ mulh_wu(a2, a4, t1);
  __ Branch(&error, ne, a2, Operand(0x3));
  __ mulh_wu(a2, a4, a6);
  __ Branch(&error, ne, a2, Operand(static_cast<int64_t>(0)));

  __ ori(a2, zero_reg, 0);
  __ mulw_d_w(a2, a4, t1);
  __ Branch(&error, ne, a2, Operand(0xFFFFFFFFFFFFB730));
  __ mulw_d_w(a2, a4, a6);
  __ Branch(&error, ne, a2, Operand(0x48D159E0));

  __ ori(a2, zero_reg, 0);
  __ mulw_d_wu(a2, a4, t1);
  __ Branch(&error, ne, a2, Operand(0x3FFFFB730));  //========0xFFFFB730
  __ ori(a2, zero_reg, 81);
  __ mulw_d_wu(a2, a4, a6);
  __ Branch(&error, ne, a2, Operand(0x48D159E0));

  __ ori(a2, zero_reg, 0);
  __ div_wu(a2, a7, a5);
  __ Branch(&error, ne, a2, Operand(0x70821));
  __ div_wu(a2, t0, a5);
  __ Branch(&error, ne, a2, Operand(0xE1042));
  __ div_wu(a2, t0, t1);
  __ Branch(&error, ne, a2, Operand(0x1));

  __ ori(a2, zero_reg, 0);
  __ mod_w(a2, a6, a5);
  __ Branch(&error, ne, a2, Operand(0xDA8));
  __ ori(a2, zero_reg, 0);
  __ mod_w(a2, t2, a5);
  __ Branch(&error, ne, a2, Operand(0xFFFFFFFFFFFFF258));
  __ ori(a2, zero_reg, 0);
  __ mod_w(a2, t2, t1);
  __ Branch(&error, ne, a2, Operand(0xFFFFFFFFFFFFF258));

  __ ori(a2, zero_reg, 0);
  __ mod_wu(a2, a6, a5);
  __ Branch(&error, ne, a2, Operand(0xDA8));
  __ mod_wu(a2, t2, a5);
  __ Branch(&error, ne, a2, Operand(0xF0));
  __ mod_wu(a2, t2, t1);
  __ Branch(&error, ne, a2, Operand(0xFFFFFFFFEDCBA988));

  __ li(a2, 0x31415926);
  __ b(&exit);

  __ bind(&error);
  __ li(a2, 0x666);

  __ bind(&exit);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  int64_t res = reinterpret_cast<int64_t>(f.Call(0, 0, 0, 0, 0));

  CHECK_EQ(0x31415926L, res);
}

TEST(LA4) {
  // Test 64bit calculate instructions.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label exit, error;

  __ li(a4, 0x17312);
  __ li(a5, 0x1012131415161718);
  __ li(a6, 0x51F4B764A26E7412);
  __ li(a7, 0x7FFFFFFFFFFFFFFF);
  __ li(t0, static_cast<int64_t>(0xFFFFFFFFFFFFF547));
  __ li(t1, static_cast<int64_t>(0xDF6B8F35A10E205C));
  __ li(t2, static_cast<int64_t>(0x81F25A87C4236841));
  __ li(t3, static_cast<int64_t>(0x8000000000000000));

  __ ori(a2, zero_reg, 0);
  __ add_d(a2, a4, a5);
  __ sub_d(a2, a2, a4);
  __ Branch(&error, ne, a2, Operand(0x1012131415161718));
  __ ori(a3, zero_reg, 0);
  __ add_d(a3, a6, a7);  //溢出
  __ Branch(&error, ne, a3, Operand(0xd1f4b764a26e7411));
  __ sub_d(a3, t3, a4);  //溢出
  __ Branch(&error, ne, a3, Operand(0x7ffffffffffe8cee));

  __ ori(a2, zero_reg, 0);
  __ addi_d(a2, a5, 0x412);  //正值
  __ Branch(&error, ne, a2, Operand(0x1012131415161b2a));
  __ addi_d(a2, a7, 0x547);  //负值
  __ Branch(&error, ne, a2, Operand(0x8000000000000546));

  __ ori(t4, zero_reg, 0);
  __ addu16i_d(a2, t4, 0x1234);
  __ Branch(&error, ne, a2, Operand(0x12340000));
  __ addu16i_d(a2, a2, 0x9876);
  __ Branch(&error, ne, a2, Operand(0xffffffffaaaa0000));

  __ ori(a2, zero_reg, 0);
  __ alsl_d(a2, t2, t0, 3);
  __ Branch(&error, ne, a2, Operand(0xf92d43e211b374f));

  __ ori(a2, zero_reg, 0);
  __ mul_d(a2, a5, a6);
  __ Branch(&error, ne, a2, Operand(0xdbe6a8729a547fb0));
  __ mul_d(a2, t0, t1);
  __ Branch(&error, ne, a2, Operand(0x57ad69f40f870584));
  __ mul_d(a2, a4, t0);
  __ Branch(&error, ne, a2, Operand(0xfffffffff07523fe));

  __ ori(a2, zero_reg, 0);
  __ mulh_d(a2, a5, a6);
  __ Branch(&error, ne, a2, Operand(0x52514c6c6b54467));
  __ mulh_d(a2, t0, t1);
  __ Branch(&error, ne, a2, Operand(0x15d));

  __ ori(a2, zero_reg, 0);
  __ mulh_du(a2, a5, a6);
  __ Branch(&error, ne, a2, Operand(0x52514c6c6b54467));
  __ mulh_du(a2, t0, t1);
  __ Branch(&error, ne, a2, Operand(0xdf6b8f35a10e1700));
  __ mulh_du(a2, a4, t0);
  __ Branch(&error, ne, a2, Operand(0x17311));

  __ ori(a2, zero_reg, 0);
  __ div_d(a2, a5, a6);
  __ Branch(&error, ne, a2, Operand(static_cast<int64_t>(0)));
  __ div_d(a2, t0, t1);
  __ Branch(&error, ne, a2, Operand(static_cast<int64_t>(0)));
  __ div_d(a2, t1, a4);
  __ Branch(&error, ne, a2, Operand(0xffffe985f631e6d9));

  __ ori(a2, zero_reg, 0);
  __ div_du(a2, a5, a6);
  __ Branch(&error, ne, a2, Operand(static_cast<int64_t>(0)));
  __ div_du(a2, t0, t1);
  __ Branch(&error, ne, a2, Operand(0x1));
  __ div_du(a2, t1, a4);
  __ Branch(&error, ne, a2, Operand(0x9a22ffd3973d));

  __ ori(a2, zero_reg, 0);
  __ mod_d(a2, a6, a4);
  __ Branch(&error, ne, a2, Operand(0x13558));
  __ mod_d(a2, t2, t0);
  __ Branch(&error, ne, a2, Operand(0xfffffffffffffb0a));
  __ mod_d(a2, t1, a4);
  __ Branch(&error, ne, a2, Operand(0xffffffffffff6a1a));

  __ ori(a2, zero_reg, 0);
  __ mod_du(a2, a6, a4);
  __ Branch(&error, ne, a2, Operand(0x13558));
  __ mod_du(a2, t2, t0);
  __ Branch(&error, ne, a2, Operand(0x81f25a87c4236841));
  __ mod_du(a2, t1, a4);
  __ Branch(&error, ne, a2, Operand(0x1712));

  // Everything was correctly executed. Load the expected result.
  __ li(a2, 0x31415926);
  __ b(&exit);

  __ bind(&error);
  __ li(a2, 0x666);
  // Got an error. Return a wrong result.

  __ bind(&exit);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  int64_t res = reinterpret_cast<int64_t>(f.Call(0, 0, 0, 0, 0));

  CHECK_EQ(0x31415926L, res);
}

TEST(LA5) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label exit, error;

  __ li(a4, 0x17312);
  __ li(a5, 0x1012131415161718);
  __ li(a6, 0x51F4B764A26E7412);
  __ li(a7, 0x7FFFFFFFFFFFFFFF);
  __ li(t0, static_cast<int64_t>(0xFFFFFFFFFFFFF547));
  __ li(t1, static_cast<int64_t>(0xDF6B8F35A10E205C));
  __ li(t2, static_cast<int64_t>(0x81F25A87C4236841));
  __ li(t3, static_cast<int64_t>(0x8000000000000000));

  __ ori(a2, zero_reg, 0);
  __ slt(a2, a5, a6);
  __ Branch(&error, ne, a2, Operand(0x1));
  __ slt(a2, a7, t0);
  __ Branch(&error, ne, a2, Operand(static_cast<int64_t>(0)));
  __ slt(a2, t1, t1);
  __ Branch(&error, ne, a2, Operand(static_cast<int64_t>(0)));

  __ ori(a2, zero_reg, 0);
  __ sltu(a2, a5, a6);
  __ Branch(&error, ne, a2, Operand(0x1));
  __ sltu(a2, a7, t0);
  __ Branch(&error, ne, a2, Operand(0x1));
  __ sltu(a2, t1, t1);
  __ Branch(&error, ne, a2, Operand(static_cast<int64_t>(0)));

  __ ori(a2, zero_reg, 0);
  __ slti(a2, a5, 0x123);
  __ Branch(&error, ne, a2, Operand(static_cast<int64_t>(0)));
  __ slti(a2, t0, 0x123);
  __ Branch(&error, ne, a2, Operand(0x1));

  __ ori(a2, zero_reg, 0);
  __ sltui(a2, a5, 0x123);
  __ Branch(&error, ne, a2, Operand(static_cast<int64_t>(0)));
  __ sltui(a2, t0, 0x123);
  __ Branch(&error, ne, a2, Operand(static_cast<int64_t>(0)));

  __ ori(a2, zero_reg, 0);
  __ and_(a2, a4, a5);
  __ Branch(&error, ne, a2, Operand(0x1310));
  __ and_(a2, a6, a7);
  __ Branch(&error, ne, a2, Operand(0x51F4B764A26E7412));

  __ ori(a2, zero_reg, 0);
  __ or_(a2, t0, t1);
  __ Branch(&error, ne, a2, Operand(0xfffffffffffff55f));
  __ or_(a2, t2, t3);
  __ Branch(&error, ne, a2, Operand(0x81f25a87c4236841));

  __ ori(a2, zero_reg, 0);
  __ nor(a2, a4, a5);
  __ Branch(&error, ne, a2, Operand(0xefedecebeae888e5));
  __ nor(a2, a6, a7);
  __ Branch(&error, ne, a2, Operand(0x8000000000000000));

  __ ori(a2, zero_reg, 0);
  __ xor_(a2, t0, t1);
  __ Branch(&error, ne, a2, Operand(0x209470ca5ef1d51b));
  __ xor_(a2, t2, t3);
  __ Branch(&error, ne, a2, Operand(0x1f25a87c4236841));

  __ ori(a2, zero_reg, 0);
  __ andn(a2, a4, a5);
  __ Branch(&error, ne, a2, Operand(0x16002));
  __ andn(a2, a6, a7);
  __ Branch(&error, ne, a2, Operand(static_cast<int64_t>(0)));

  __ ori(a2, zero_reg, 0);
  __ orn(a2, t0, t1);
  __ Branch(&error, ne, a2, Operand(0xffffffffffffffe7));
  __ orn(a2, t2, t3);
  __ Branch(&error, ne, a2, Operand(0xffffffffffffffff));

  __ ori(a2, zero_reg, 0);
  __ andi(a2, a4, 0x123);
  __ Branch(&error, ne, a2, Operand(0x102));
  __ andi(a2, a6, 0xDCB);
  __ Branch(&error, ne, a2, Operand(0x402));

  __ ori(a2, zero_reg, 0);
  __ xori(a2, t0, 0x123);
  __ Branch(&error, ne, a2, Operand(0xfffffffffffff464));
  __ xori(a2, t2, 0xDCB);
  __ Branch(&error, ne, a2, Operand(0x81f25a87c423658a));

  // Everything was correctly executed. Load the expected result.
  __ li(a2, 0x31415926);
  __ b(&exit);

  __ bind(&error);
  // Got an error. Return a wrong result.
  __ li(a2, 0x666);

  __ bind(&exit);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  int64_t res = reinterpret_cast<int64_t>(f.Call(0, 0, 0, 0, 0));

  CHECK_EQ(0x31415926L, res);
}

TEST(LA6) {
  // Test loads and stores instruction.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct T {
    int64_t si1;
    int64_t si2;
    int64_t si3;
    int64_t result_ld_b_si1;
    int64_t result_ld_b_si2;
    int64_t result_ld_h_si1;
    int64_t result_ld_h_si2;
    int64_t result_ld_w_si1;
    int64_t result_ld_w_si2;
    int64_t result_ld_d_si1;
    int64_t result_ld_d_si3;
    int64_t result_ld_bu_si2;
    int64_t result_ld_hu_si2;
    int64_t result_ld_wu_si2;
    int64_t result_st_b;
    int64_t result_st_h;
    int64_t result_st_w;
  };
  T t;

  // Ld_b
  __ Ld_b(a4, MemOperand(a0, offsetof(T, si1)));
  __ St_d(a4, MemOperand(a0, offsetof(T, result_ld_b_si1)));

  __ Ld_b(a4, MemOperand(a0, offsetof(T, si2)));
  __ St_d(a4, MemOperand(a0, offsetof(T, result_ld_b_si2)));

  // Ld_h
  __ Ld_h(a5, MemOperand(a0, offsetof(T, si1)));
  __ St_d(a5, MemOperand(a0, offsetof(T, result_ld_h_si1)));

  __ Ld_h(a5, MemOperand(a0, offsetof(T, si2)));
  __ St_d(a5, MemOperand(a0, offsetof(T, result_ld_h_si2)));

  // Ld_w
  __ Ld_w(a6, MemOperand(a0, offsetof(T, si1)));
  __ St_d(a6, MemOperand(a0, offsetof(T, result_ld_w_si1)));

  __ Ld_w(a6, MemOperand(a0, offsetof(T, si2)));
  __ St_d(a6, MemOperand(a0, offsetof(T, result_ld_w_si2)));

  // Ld_d
  __ Ld_d(a7, MemOperand(a0, offsetof(T, si1)));
  __ St_d(a7, MemOperand(a0, offsetof(T, result_ld_d_si1)));

  __ Ld_d(a7, MemOperand(a0, offsetof(T, si3)));
  __ St_d(a7, MemOperand(a0, offsetof(T, result_ld_d_si3)));

  // Ld_bu
  __ Ld_bu(t0, MemOperand(a0, offsetof(T, si2)));
  __ St_d(t0, MemOperand(a0, offsetof(T, result_ld_bu_si2)));

  // Ld_hu
  __ Ld_hu(t1, MemOperand(a0, offsetof(T, si2)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_ld_hu_si2)));

  // Ld_wu
  __ Ld_wu(t2, MemOperand(a0, offsetof(T, si2)));
  __ St_d(t2, MemOperand(a0, offsetof(T, result_ld_wu_si2)));

  // St
  __ li(t4, 0x11111111);

  // St_b
  __ Ld_d(t5, MemOperand(a0, offsetof(T, si3)));
  __ St_d(t5, MemOperand(a0, offsetof(T, result_st_b)));
  __ St_b(t4, MemOperand(a0, offsetof(T, result_st_b)));

  // St_h
  __ Ld_d(t6, MemOperand(a0, offsetof(T, si3)));
  __ St_d(t6, MemOperand(a0, offsetof(T, result_st_h)));
  __ St_h(t4, MemOperand(a0, offsetof(T, result_st_h)));

  // St_w
  __ Ld_d(t7, MemOperand(a0, offsetof(T, si3)));
  __ St_d(t7, MemOperand(a0, offsetof(T, result_st_w)));
  __ St_w(t4, MemOperand(a0, offsetof(T, result_st_w)));

  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  t.si1 = 0x11223344;
  t.si2 = 0x99AABBCC;
  t.si3 = 0x1122334455667788;
  f.Call(&t, 0, 0, 0, 0);

  CHECK_EQ(static_cast<int64_t>(0x44), t.result_ld_b_si1);
  CHECK_EQ(static_cast<int64_t>(0xFFFFFFFFFFFFFFCC), t.result_ld_b_si2);

  CHECK_EQ(static_cast<int64_t>(0x3344), t.result_ld_h_si1);
  CHECK_EQ(static_cast<int64_t>(0xFFFFFFFFFFFFBBCC), t.result_ld_h_si2);

  CHECK_EQ(static_cast<int64_t>(0x11223344), t.result_ld_w_si1);
  CHECK_EQ(static_cast<int64_t>(0xFFFFFFFF99AABBCC), t.result_ld_w_si2);

  CHECK_EQ(static_cast<int64_t>(0x11223344), t.result_ld_d_si1);
  CHECK_EQ(static_cast<int64_t>(0x1122334455667788), t.result_ld_d_si3);

  CHECK_EQ(static_cast<int64_t>(0xCC), t.result_ld_bu_si2);
  CHECK_EQ(static_cast<int64_t>(0xBBCC), t.result_ld_hu_si2);
  CHECK_EQ(static_cast<int64_t>(0x99AABBCC), t.result_ld_wu_si2);

  CHECK_EQ(static_cast<int64_t>(0x1122334455667711), t.result_st_b);
  CHECK_EQ(static_cast<int64_t>(0x1122334455661111), t.result_st_h);
  CHECK_EQ(static_cast<int64_t>(0x1122334411111111), t.result_st_w);
}

TEST(LA7) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct T {
    int64_t si1;
    int64_t si2;
    int64_t si3;
    int64_t result_ldx_b_si1;
    int64_t result_ldx_b_si2;
    int64_t result_ldx_h_si1;
    int64_t result_ldx_h_si2;
    int64_t result_ldx_w_si1;
    int64_t result_ldx_w_si2;
    int64_t result_ldx_d_si1;
    int64_t result_ldx_d_si3;
    int64_t result_ldx_bu_si2;
    int64_t result_ldx_hu_si2;
    int64_t result_ldx_wu_si2;
    int64_t result_stx_b;
    int64_t result_stx_h;
    int64_t result_stx_w;
  };
  T t;

  // ldx_b
  __ li(a2, static_cast<int64_t>(offsetof(T, si1)));
  __ Ld_b(a4, MemOperand(a0, a2));
  __ St_d(a4, MemOperand(a0, offsetof(T, result_ldx_b_si1)));

  __ li(a2, static_cast<int64_t>(offsetof(T, si2)));
  __ Ld_b(a4, MemOperand(a0, a2));
  __ St_d(a4, MemOperand(a0, offsetof(T, result_ldx_b_si2)));

  // ldx_h
  __ li(a2, static_cast<int64_t>(offsetof(T, si1)));
  __ Ld_h(a5, MemOperand(a0, a2));
  __ St_d(a5, MemOperand(a0, offsetof(T, result_ldx_h_si1)));

  __ li(a2, static_cast<int64_t>(offsetof(T, si2)));
  __ Ld_h(a5, MemOperand(a0, a2));
  __ St_d(a5, MemOperand(a0, offsetof(T, result_ldx_h_si2)));

  // ldx_w
  __ li(a2, static_cast<int64_t>(offsetof(T, si1)));
  __ Ld_w(a6, MemOperand(a0, a2));
  __ St_d(a6, MemOperand(a0, offsetof(T, result_ldx_w_si1)));

  __ li(a2, static_cast<int64_t>(offsetof(T, si2)));
  __ Ld_w(a6, MemOperand(a0, a2));
  __ St_d(a6, MemOperand(a0, offsetof(T, result_ldx_w_si2)));

  // Ld_d
  __ li(a2, static_cast<int64_t>(offsetof(T, si1)));
  __ Ld_d(a7, MemOperand(a0, a2));
  __ St_d(a7, MemOperand(a0, offsetof(T, result_ldx_d_si1)));

  __ li(a2, static_cast<int64_t>(offsetof(T, si3)));
  __ Ld_d(a7, MemOperand(a0, a2));
  __ St_d(a7, MemOperand(a0, offsetof(T, result_ldx_d_si3)));

  // Ld_bu
  __ li(a2, static_cast<int64_t>(offsetof(T, si2)));
  __ Ld_bu(t0, MemOperand(a0, a2));
  __ St_d(t0, MemOperand(a0, offsetof(T, result_ldx_bu_si2)));

  // Ld_hu
  __ li(a2, static_cast<int64_t>(offsetof(T, si2)));
  __ Ld_hu(t1, MemOperand(a0, a2));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_ldx_hu_si2)));

  // Ld_wu
  __ li(a2, static_cast<int64_t>(offsetof(T, si2)));
  __ Ld_wu(t2, MemOperand(a0, a2));
  __ St_d(t2, MemOperand(a0, offsetof(T, result_ldx_wu_si2)));

  // St
  __ li(t4, 0x11111111);

  // St_b
  __ Ld_d(t5, MemOperand(a0, offsetof(T, si3)));
  __ St_d(t5, MemOperand(a0, offsetof(T, result_stx_b)));
  __ li(a2, static_cast<int64_t>(offsetof(T, result_stx_b)));
  __ St_b(t4, MemOperand(a0, a2));

  // St_h
  __ Ld_d(t6, MemOperand(a0, offsetof(T, si3)));
  __ St_d(t6, MemOperand(a0, offsetof(T, result_stx_h)));
  __ li(a2, static_cast<int64_t>(offsetof(T, result_stx_h)));
  __ St_h(t4, MemOperand(a0, a2));

  // St_w
  __ Ld_d(t7, MemOperand(a0, offsetof(T, si3)));
  __ li(a2, static_cast<int64_t>(offsetof(T, result_stx_w)));
  __ St_d(t7, MemOperand(a0, a2));
  __ li(a3, static_cast<int64_t>(offsetof(T, result_stx_w)));
  __ St_w(t4, MemOperand(a0, a3));

  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  t.si1 = 0x11223344;
  t.si2 = 0x99AABBCC;
  t.si3 = 0x1122334455667788;
  f.Call(&t, 0, 0, 0, 0);

  CHECK_EQ(static_cast<int64_t>(0x44), t.result_ldx_b_si1);
  CHECK_EQ(static_cast<int64_t>(0xFFFFFFFFFFFFFFCC), t.result_ldx_b_si2);

  CHECK_EQ(static_cast<int64_t>(0x3344), t.result_ldx_h_si1);
  CHECK_EQ(static_cast<int64_t>(0xFFFFFFFFFFFFBBCC), t.result_ldx_h_si2);

  CHECK_EQ(static_cast<int64_t>(0x11223344), t.result_ldx_w_si1);
  CHECK_EQ(static_cast<int64_t>(0xFFFFFFFF99AABBCC), t.result_ldx_w_si2);

  CHECK_EQ(static_cast<int64_t>(0x11223344), t.result_ldx_d_si1);
  CHECK_EQ(static_cast<int64_t>(0x1122334455667788), t.result_ldx_d_si3);

  CHECK_EQ(static_cast<int64_t>(0xCC), t.result_ldx_bu_si2);
  CHECK_EQ(static_cast<int64_t>(0xBBCC), t.result_ldx_hu_si2);
  CHECK_EQ(static_cast<int64_t>(0x99AABBCC), t.result_ldx_wu_si2);

  CHECK_EQ(static_cast<int64_t>(0x1122334455667711), t.result_stx_b);
  CHECK_EQ(static_cast<int64_t>(0x1122334455661111), t.result_stx_h);
  CHECK_EQ(static_cast<int64_t>(0x1122334411111111), t.result_stx_w);
}

TEST(LDPTR_STPTR) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  int64_t test[10];

  __ ldptr_w(a4, a0, 0);
  __ stptr_d(a4, a0, 24);  // test[3]

  __ ldptr_w(a5, a0, 8);   // test[1]
  __ stptr_d(a5, a0, 32);  // test[4]

  __ ldptr_d(a6, a0, 16);  // test[2]
  __ stptr_d(a6, a0, 40);  // test[5]

  __ li(t0, 0x11111111);

  __ stptr_d(a6, a0, 48);  // test[6]
  __ stptr_w(t0, a0, 48);  // test[6]

  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  test[0] = 0x11223344;
  test[1] = 0x99AABBCC;
  test[2] = 0x1122334455667788;
  f.Call(&test, 0, 0, 0, 0);

  CHECK_EQ(static_cast<int64_t>(0x11223344), test[3]);
  CHECK_EQ(static_cast<int64_t>(0xFFFFFFFF99AABBCC), test[4]);
  CHECK_EQ(static_cast<int64_t>(0x1122334455667788), test[5]);
  CHECK_EQ(static_cast<int64_t>(0x1122334411111111), test[6]);
}

TEST(LA8) {
  // Test 32bit shift instructions.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    int32_t input;
    int32_t result_sll_w_0;
    int32_t result_sll_w_8;
    int32_t result_sll_w_10;
    int32_t result_sll_w_31;
    int32_t result_srl_w_0;
    int32_t result_srl_w_8;
    int32_t result_srl_w_10;
    int32_t result_srl_w_31;
    int32_t result_sra_w_0;
    int32_t result_sra_w_8;
    int32_t result_sra_w_10;
    int32_t result_sra_w_31;
    int32_t result_rotr_w_0;
    int32_t result_rotr_w_8;
    int32_t result_slli_w_0;
    int32_t result_slli_w_8;
    int32_t result_slli_w_10;
    int32_t result_slli_w_31;
    int32_t result_srli_w_0;
    int32_t result_srli_w_8;
    int32_t result_srli_w_10;
    int32_t result_srli_w_31;
    int32_t result_srai_w_0;
    int32_t result_srai_w_8;
    int32_t result_srai_w_10;
    int32_t result_srai_w_31;
    int32_t result_rotri_w_0;
    int32_t result_rotri_w_8;
    int32_t result_rotri_w_10;
    int32_t result_rotri_w_31;
  };
  T t;
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  __ Ld_w(a4, MemOperand(a0, offsetof(T, input)));

  // sll_w
  __ li(a5, 0);
  __ sll_w(t0, a4, a5);
  __ li(a5, 0x8);
  __ sll_w(t1, a4, a5);
  __ li(a5, 0xA);
  __ sll_w(t2, a4, a5);
  __ li(a5, 0x1F);
  __ sll_w(t3, a4, a5);

  __ St_w(t0, MemOperand(a0, offsetof(T, result_sll_w_0)));
  __ St_w(t1, MemOperand(a0, offsetof(T, result_sll_w_8)));
  __ St_w(t2, MemOperand(a0, offsetof(T, result_sll_w_10)));
  __ St_w(t3, MemOperand(a0, offsetof(T, result_sll_w_31)));

  // srl_w
  __ li(a5, 0x0);
  __ srl_w(t0, a4, a5);
  __ li(a5, 0x8);
  __ srl_w(t1, a4, a5);
  __ li(a5, 0xA);
  __ srl_w(t2, a4, a5);
  __ li(a5, 0x1F);
  __ srl_w(t3, a4, a5);

  __ St_w(t0, MemOperand(a0, offsetof(T, result_srl_w_0)));
  __ St_w(t1, MemOperand(a0, offsetof(T, result_srl_w_8)));
  __ St_w(t2, MemOperand(a0, offsetof(T, result_srl_w_10)));
  __ St_w(t3, MemOperand(a0, offsetof(T, result_srl_w_31)));

  // sra_w
  __ li(a5, 0x0);
  __ sra_w(t0, a4, a5);
  __ li(a5, 0x8);
  __ sra_w(t1, a4, a5);

  __ li(a6, static_cast<int32_t>(0x80000000));
  __ add_w(a6, a6, a4);
  __ li(a5, 0xA);
  __ sra_w(t2, a6, a5);
  __ li(a5, 0x1F);
  __ sra_w(t3, a6, a5);

  __ St_w(t0, MemOperand(a0, offsetof(T, result_sra_w_0)));
  __ St_w(t1, MemOperand(a0, offsetof(T, result_sra_w_8)));
  __ St_w(t2, MemOperand(a0, offsetof(T, result_sra_w_10)));
  __ St_w(t3, MemOperand(a0, offsetof(T, result_sra_w_31)));

  // rotr
  __ li(a5, 0x0);
  __ rotr_w(t0, a4, a5);
  __ li(a6, 0x8);
  __ rotr_w(t1, a4, a6);

  __ St_w(t0, MemOperand(a0, offsetof(T, result_rotr_w_0)));
  __ St_w(t1, MemOperand(a0, offsetof(T, result_rotr_w_8)));

  // slli_w
  __ slli_w(t0, a4, 0);
  __ slli_w(t1, a4, 0x8);
  __ slli_w(t2, a4, 0xA);
  __ slli_w(t3, a4, 0x1F);

  __ St_w(t0, MemOperand(a0, offsetof(T, result_slli_w_0)));
  __ St_w(t1, MemOperand(a0, offsetof(T, result_slli_w_8)));
  __ St_w(t2, MemOperand(a0, offsetof(T, result_slli_w_10)));
  __ St_w(t3, MemOperand(a0, offsetof(T, result_slli_w_31)));

  // srli_w
  __ srli_w(t0, a4, 0);
  __ srli_w(t1, a4, 0x8);
  __ srli_w(t2, a4, 0xA);
  __ srli_w(t3, a4, 0x1F);

  __ St_w(t0, MemOperand(a0, offsetof(T, result_srli_w_0)));
  __ St_w(t1, MemOperand(a0, offsetof(T, result_srli_w_8)));
  __ St_w(t2, MemOperand(a0, offsetof(T, result_srli_w_10)));
  __ St_w(t3, MemOperand(a0, offsetof(T, result_srli_w_31)));

  // srai_w
  __ srai_w(t0, a4, 0);
  __ srai_w(t1, a4, 0x8);

  __ li(a6, static_cast<int32_t>(0x80000000));
  __ add_w(a6, a6, a4);
  __ srai_w(t2, a6, 0xA);
  __ srai_w(t3, a6, 0x1F);

  __ St_w(t0, MemOperand(a0, offsetof(T, result_srai_w_0)));
  __ St_w(t1, MemOperand(a0, offsetof(T, result_srai_w_8)));
  __ St_w(t2, MemOperand(a0, offsetof(T, result_srai_w_10)));
  __ St_w(t3, MemOperand(a0, offsetof(T, result_srai_w_31)));

  // rotri_w
  __ rotri_w(t0, a4, 0);
  __ rotri_w(t1, a4, 0x8);
  __ rotri_w(t2, a4, 0xA);
  __ rotri_w(t3, a4, 0x1F);

  __ St_w(t0, MemOperand(a0, offsetof(T, result_rotri_w_0)));
  __ St_w(t1, MemOperand(a0, offsetof(T, result_rotri_w_8)));
  __ St_w(t2, MemOperand(a0, offsetof(T, result_rotri_w_10)));
  __ St_w(t3, MemOperand(a0, offsetof(T, result_rotri_w_31)));

  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  t.input = 0x12345678;
  f.Call(&t, 0x0, 0, 0, 0);

  CHECK_EQ(static_cast<int32_t>(0x12345678), t.result_sll_w_0);
  CHECK_EQ(static_cast<int32_t>(0x34567800), t.result_sll_w_8);
  CHECK_EQ(static_cast<int32_t>(0xD159E000), t.result_sll_w_10);
  CHECK_EQ(static_cast<int32_t>(0x0), t.result_sll_w_31);

  CHECK_EQ(static_cast<int32_t>(0x12345678), t.result_srl_w_0);
  CHECK_EQ(static_cast<int32_t>(0x123456), t.result_srl_w_8);
  CHECK_EQ(static_cast<int32_t>(0x48D15), t.result_srl_w_10);
  CHECK_EQ(static_cast<int32_t>(0x0), t.result_srl_w_31);

  CHECK_EQ(static_cast<int32_t>(0x12345678), t.result_sra_w_0);
  CHECK_EQ(static_cast<int32_t>(0x123456), t.result_sra_w_8);
  CHECK_EQ(static_cast<int32_t>(0xFFE48D15), t.result_sra_w_10);
  CHECK_EQ(static_cast<int32_t>(0xFFFFFFFF), t.result_sra_w_31);

  CHECK_EQ(static_cast<int32_t>(0x12345678), t.result_rotr_w_0);
  CHECK_EQ(static_cast<int32_t>(0x78123456), t.result_rotr_w_8);

  CHECK_EQ(static_cast<int32_t>(0x12345678), t.result_slli_w_0);
  CHECK_EQ(static_cast<int32_t>(0x34567800), t.result_slli_w_8);
  CHECK_EQ(static_cast<int32_t>(0xD159E000), t.result_slli_w_10);
  CHECK_EQ(static_cast<int32_t>(0x0), t.result_slli_w_31);

  CHECK_EQ(static_cast<int32_t>(0x12345678), t.result_srli_w_0);
  CHECK_EQ(static_cast<int32_t>(0x123456), t.result_srli_w_8);
  CHECK_EQ(static_cast<int32_t>(0x48D15), t.result_srli_w_10);
  CHECK_EQ(static_cast<int32_t>(0x0), t.result_srli_w_31);

  CHECK_EQ(static_cast<int32_t>(0x12345678), t.result_srai_w_0);
  CHECK_EQ(static_cast<int32_t>(0x123456), t.result_srai_w_8);
  CHECK_EQ(static_cast<int32_t>(0xFFE48D15), t.result_srai_w_10);
  CHECK_EQ(static_cast<int32_t>(0xFFFFFFFF), t.result_srai_w_31);

  CHECK_EQ(static_cast<int32_t>(0x12345678), t.result_rotri_w_0);
  CHECK_EQ(static_cast<int32_t>(0x78123456), t.result_rotri_w_8);
  CHECK_EQ(static_cast<int32_t>(0x9E048D15), t.result_rotri_w_10);
  CHECK_EQ(static_cast<int32_t>(0x2468ACF0), t.result_rotri_w_31);
}

TEST(LA9) {
  // Test 64bit shift instructions.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    int64_t input;
    int64_t result_sll_d_0;
    int64_t result_sll_d_13;
    int64_t result_sll
```