Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

**1. Initial Understanding (Skimming and Keywords):**

* **Copyright and License:**  Recognize standard open-source licensing boilerplate. Not directly functional, but good to acknowledge.
* **Includes:**  `#include` statements are crucial. They point to the code's dependencies and hints at its purpose. Look for key headers like:
    * `"src/codegen/assembler-inl.h"`, `"src/codegen/macro-assembler.h"`: Strong indicators of assembly code generation.
    * `"src/execution/simulator.h"`:  Suggests the code might be testing or working with a simulator environment for executing generated code.
    * `"test/cctest/cctest.h"`, `"test/cctest/test-helper-riscv32.h"`:  Confirms this is a *test* file, specifically for the RISC-V 32-bit architecture.
* **Namespaces:** `v8::internal`. This tells us the code is part of V8's internal implementation, not the public API.
* **Constants:**  Definitions like `qnan_f`, `inf_d` suggest the code deals with floating-point numbers and their special values (NaN, infinity).
* **`using FV`, `using F1`, etc.:**  These are type aliases for function pointers. The names and parameter lists (especially `int32_t`, `void*`) reinforce the idea of low-level operations and passing data to generated code.
* **`#define __ masm.`:**  A common shorthand for using the `MacroAssembler` object.
* **`TEST(...)` macros:**  Immediately identify this as a test suite, with individual test cases. The names of the tests are very informative (e.g., `LoadConstants`, `LoadAddress`, `jump_tables4`, `CalcScaledAddress`, `OverflowInstructions`, `Ulw`, `ULoadFloat`).

**2. Deeper Dive into Key Sections:**

* **`run_CalcScaledAddress`:**  This function clearly generates assembly code using `CalcScaledAddress` and then executes it. The inputs (`rt`, `rs`, `sa`) and the output (`res`) suggest it's testing an instruction or macro for calculating scaled memory addresses.
* **`run_Unaligned`:** This function deals with unaligned memory access. The template parameters (`VTYPE`, `Func`) and the logic of copying data into a buffer and then running generated code point to testing how unaligned loads and stores are handled.
* **`LoadConstants`:**  The code generates assembly to load various constant values into memory. This tests the `li` (load immediate) instruction and how constants are handled.
* **`LoadAddress`:** This test focuses on loading the address of a label, likely testing how relative addressing and internal references are encoded.
* **`jump_tables*`:** These tests are explicitly named for jump tables. They test how V8 generates efficient code for switch statements or similar control flow structures. The comments mention "trampolines," indicating they are testing how the assembler handles long jumps.
* **`CalcScaledAddress` Test:**  This test provides specific input values and expected outputs, allowing us to understand the behavior of the `CalcScaledAddress` instruction for different combinations of registers and scale factors, including edge cases like overflow.
* **`Cvt_s_uw_Trunc_uw_s` and `cvt_d_w_Trunc_w_d`:**  These tests are about converting between integer and floating-point types, specifically unsigned word to single-precision float and word to double-precision float, followed by truncation back to integer.
* **`OverflowInstructions`:**  This section directly tests instructions designed to detect arithmetic overflow (`AddOverflow`, `SubOverflow`, `MulOverflow32`). The test structure iterates through various inputs and compares the results with expected overflow flags and values.
* **`min_max_nan`:**  This test focuses on the `Float64Min`, `Float64Max`, `Float32Min`, and `Float32Max` macros, paying particular attention to how they handle special floating-point values like NaN, positive zero, and negative zero.
* **`Ulh`, `Ulw`, `ULoadFloat`, `ULoadDouble`:**  These tests are all prefixed with "U," likely standing for "Unaligned."  They test the unaligned load and store instructions for different data sizes (half-word, word, float, double).
* **`Sltu`:** This tests the "Set Less Than Unsigned" instruction, comparing unsigned integers.
* **`macro_float_minmax_f32`:** This test examines the behavior of the `Float32Min` and `Float32Max` macros with various register assignments, ensuring the macro works correctly in different scenarios.

**3. Inferring Overall Functionality:**

Based on the individual tests, the overarching function of `test-macro-assembler-riscv32.cc` is clearly to **test the correctness and functionality of the RISC-V 32-bit macro assembler in V8.** This involves:

* **Verifying individual instructions and macros:** Testing if each instruction (like `li`, `add`, `lw`, `sw`, floating-point operations) and higher-level macros (like `CalcScaledAddress`, `AddOverflow`, `Float32Min`) produce the expected results.
* **Testing edge cases and special conditions:**  Specifically targeting scenarios like arithmetic overflow, unaligned memory access, handling of NaN and infinity, and long jumps.
* **Ensuring correct code generation:** Checking that the assembler produces the correct sequence of machine instructions for different code patterns.
* **Validating register allocation and usage:** Some tests explicitly check how registers are used and if there are any conflicts or incorrect assumptions.

**4. Answering Specific Questions:**

* **Functionality:**  (As described above - testing the RISC-V 32-bit macro assembler.)
* **`.tq` Extension:** The code does *not* end in `.tq`. Therefore, it is **not a V8 Torque source file.**
* **Relationship to JavaScript:** This code is part of V8's *internal* implementation. While it doesn't directly execute JavaScript, the correctness of the macro assembler is **fundamental to V8's ability to compile and run JavaScript code on RISC-V 32-bit architectures efficiently.**  The assembler is used by the compiler to translate JavaScript into machine code.
* **JavaScript Example (Illustrative):**  A simple JavaScript function like `function add(a, b) { return a + b; }` might, on a RISC-V 32-bit system, be compiled down to machine code that uses instructions tested in this file (e.g., addition instructions, potentially overflow-checking instructions if optimizations don't remove them).
* **Code Logic Inference (Example - `CalcScaledAddress`):**
    * **Assumption:** `CalcScaledAddress(rd, rn, rm, shift_amount)` calculates `rd = rn + (rm << shift_amount)`.
    * **Input (from the test):** `rt = 0x4`, `rs = 0x1`, `sa = 1`.
    * **Output (expected):** `0x6` (because `0x4 + (0x1 << 1) = 0x4 + 0x2 = 0x6`).
* **Common Programming Errors:**
    * **Unaligned Access:**  Trying to read or write data at memory addresses that are not multiples of the data size (e.g., reading a 4-byte integer from an odd address). The `Ulw`, `Ulh` tests directly relate to this.
    * **Integer Overflow:** Performing arithmetic operations that result in a value outside the representable range of the integer type. The `OverflowInstructions` test is designed to catch this.
* **Summary of Functionality (Part 1):** The code in this first part focuses on testing basic arithmetic and logical operations, memory access instructions (including unaligned access), constant loading, address loading, jump tables, and integer/floating-point conversions within the RISC-V 32-bit macro assembler. It lays the groundwork for more complex functionality tested in later parts (presumably).

This detailed thought process, starting with a high-level overview and drilling down into specific code sections, helps to thoroughly understand the purpose and functionality of the provided source code.
这是一个V8项目中针对RISC-V 32位架构的宏汇编器测试文件。它包含了大量的单元测试，旨在验证 `MacroAssembler` 类在 RISC-V 32位架构上的各种功能和指令的正确性。

**以下是其主要功能归纳：**

1. **指令测试:**  测试了 RISC-V 32位架构的各种指令，包括但不限于：
    * **算术运算指令:**  加法 (`add`, `addi`), 减法 (`sub`), 乘法 (`mul`) 以及带有溢出检测的指令 (`AddOverflow`, `SubOverflow`, `MulOverflow32`)。
    * **逻辑运算指令:**  比较指令 (`Sltu`)。
    * **内存访问指令:**  加载 (`lw`, `lh`, `lb`, `ulw`, `ulh`) 和存储 (`sw`, `sh`, `sb`, `usw`, `ush`) 指令，特别包括了对非对齐内存访问指令 (`Ulw`, `Ulh`, `ULoadFloat`, `ULoadDouble`) 的测试。
    * **浮点运算指令:**  浮点数的加载、存储、比较、最小值、最大值以及类型转换指令 (`Cvt_s_uw`, `Trunc_uw_s`, `fcvt_d_w`, `Trunc_w_d`, `Float32Min`, `Float32Max`, `Float64Min`, `Float64Max`)。
    * **跳转和分支指令:**  无条件跳转 (`j`, `jr`) 和条件分支指令 (`beq`, `bne` 等，虽然代码中未直接体现，但 jump_tables 的测试间接覆盖)。
    * **立即数加载指令:**  `li` 指令用于加载常量。
    * **地址计算指令:**  `CalcScaledAddress` 用于计算缩放地址。
    * **其他指令:**  `nop` (空操作), `stop` (停止执行，用于测试)。

2. **宏测试:**  测试了宏汇编器提供的一些宏，例如 `CalcScaledAddress`，以及用于处理浮点数最小值和最大值的宏 (`Float32Min`, `Float32Max`, `Float64Min`, `Float64Max`)。

3. **非对齐内存访问测试:**  重点测试了 RISC-V 32位架构上处理非对齐内存访问的能力，确保 `Ulw`, `Ulh`, `ULoadFloat`, `ULoadDouble` 和对应的存储指令能够正确工作。

4. **跳转表测试:**  测试了生成跳转表 (`GenerateSwitchTable`) 的功能，这对于实现高效的 `switch` 语句或虚函数调用非常重要。测试用例特别关注了跳转距离过长时，宏汇编器是否能够正确生成跳转桩 (trampoline)。

5. **常量加载测试:**  验证了加载各种常量值的功能。

6. **地址加载测试:**  测试了加载代码标签地址的功能，这对于实现函数调用和跳转非常关键。

**如果 `v8/test/cctest/test-macro-assembler-riscv32.cc` 以 `.tq` 结尾，那它是个 v8 torque 源代码。** 但根据你提供的文件名，它以 `.cc` 结尾，因此是 C++ 源代码。Torque 是一种 V8 内部使用的领域特定语言，用于生成高效的运行时代码。

**与 Javascript 的功能关系：**

这个测试文件直接测试的是 V8 引擎的底层代码生成部分，也就是将高级语言（包括 JavaScript）编译成机器码的关键组件。`MacroAssembler` 类是 V8 中用于生成 RISC-V 32位机器码的核心工具。

例如，考虑以下 JavaScript 代码：

```javascript
function multiply(a, b) {
  return a * b;
}
```

当 V8 引擎在 RISC-V 32位架构上编译这个函数时，`MacroAssembler` 可能会被用来生成类似以下的 RISC-V 汇编指令（简化示例）：

```assembly
  # 假设 a 在寄存器 a0， b 在寄存器 a1
  mulw a2, a0, a1  # 将 a0 和 a1 的值相乘，结果放入 a2
  mv a0, a2       # 将结果从 a2 移动到返回值寄存器 a0
  ret             # 返回
```

`test-macro-assembler-riscv32.cc` 中的 `TEST(OverflowInstructions)` 测试用例，则直接验证了类似 `mulw` 这样的乘法指令以及溢出检测指令 (`MulOverflow32`) 的正确性，确保 V8 在执行 JavaScript 乘法运算时不会出现错误。

**代码逻辑推理（以 `CalcScaledAddress` 测试为例）：**

**假设输入：** `rt = 0x4`, `rs = 0x1`, `sa = 1`

**代码逻辑：** `CalcScaledAddress(a0, a0, a1, sa)`  这条宏指令在 RISC-V 32位架构上通常会计算 `a0 = a0 + (a1 << sa)`。

**推理过程：**
1. 初始时，`a0` 的值为 `rt` (0x4)，`a1` 的值为 `rs` (0x1)，`sa` 为 1。
2. `a1 << sa`  即 `0x1 << 1`，结果为 `0x2`。
3. `a0 + (a1 << sa)` 即 `0x4 + 0x2`，结果为 `0x6`。

**预期输出：** `res = 0x6`

**涉及用户常见的编程错误（以非对齐内存访问为例）：**

用户在编写 C/C++ 代码时，如果错误地将指向数据的指针进行类型转换，可能会导致非对齐内存访问。例如：

```c++
#include <iostream>
#include <cstring>

int main() {
  char buffer[5];
  int value = 0x12345678;

  // 将整数复制到字符数组
  std::memcpy(buffer + 1, &value, sizeof(int));

  // 尝试将字符数组中非对齐的内存地址解释为整数指针
  int* ptr = reinterpret_cast<int*>(buffer + 1);
  int read_value = *ptr; // 可能会导致程序崩溃或产生未定义的行为

  std::cout << std::hex << read_value << std::endl;
  return 0;
}
```

在某些架构上，直接访问非对齐的内存地址会导致硬件异常。V8 的 `test-macro-assembler-riscv32.cc` 中的 `TEST(Ulw)` 等测试用例，正是为了验证 V8 的代码生成器能够正确地处理这种情况，可能通过生成特殊的指令序列来安全地访问非对齐的内存。

**功能归纳（第 1 部分）：**

总而言之，`v8/test/cctest/test-macro-assembler-riscv32.cc` 的第 1 部分主要功能是 **系统地测试 V8 引擎中 RISC-V 32位宏汇编器的基础指令、宏以及对非对齐内存访问的处理能力。** 这些测试覆盖了算术运算、逻辑运算、内存访问、浮点运算、跳转控制和常量加载等核心功能，确保 V8 能够为 RISC-V 32位架构生成正确且高效的机器码。

### 提示词
```
这是目录为v8/test/cctest/test-macro-assembler-riscv32.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-macro-assembler-riscv32.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
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
#include "src/deoptimizer/deoptimizer.h"
#include "src/execution/simulator.h"
#include "src/init/v8.h"
#include "src/objects/heap-number.h"
#include "src/objects/objects-inl.h"
#include "src/utils/ostreams.h"
#include "test/cctest/cctest.h"
#include "test/cctest/test-helper-riscv32.h"
#include "test/common/assembler-tester.h"
#include "test/common/value-helper.h"

namespace v8 {
namespace internal {

const float qnan_f = std::numeric_limits<float>::quiet_NaN();
const float snan_f = std::numeric_limits<float>::signaling_NaN();
const double qnan_d = std::numeric_limits<double>::quiet_NaN();
// const double snan_d = std::numeric_limits<double>::signaling_NaN();

const float inf_f = std::numeric_limits<float>::infinity();
const double inf_d = std::numeric_limits<double>::infinity();
const float minf_f = -inf_f;
const double minf_d = -inf_d;

using FV = void*(int32_t x, int32_t y, int p2, int p3, int p4);
using F1 = void*(int x, int p1, int p2, int p3, int p4);
using F3 = void*(void* p, int p1, int p2, int p3, int p4);
using F4 = void*(void* p0, void* p1, int p2, int p3, int p4);

#define __ masm.
static uint32_t run_CalcScaledAddress(uint32_t rt, uint32_t rs, int8_t sa) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  auto fn = [sa](MacroAssembler& masm) {
    __ CalcScaledAddress(a0, a0, a1, sa);
  };
  auto f = AssembleCode<FV>(isolate, fn);

  uint32_t res = reinterpret_cast<uint32_t>(f.Call(rt, rs, 0, 0, 0));

  return res;
}

template <typename VTYPE, typename Func>
VTYPE run_Unaligned(char* memory_buffer, int32_t in_offset, int32_t out_offset,
                    VTYPE value, Func GenerateUnalignedInstructionFunc) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  auto fn = [in_offset, out_offset,
             GenerateUnalignedInstructionFunc](MacroAssembler& masm) {
    GenerateUnalignedInstructionFunc(masm, in_offset, out_offset);
  };
  auto f = AssembleCode<int32_t(char*)>(isolate, fn);

  MemCopy(memory_buffer + in_offset, &value, sizeof(VTYPE));
  f.Call(memory_buffer);
  VTYPE res;
  MemCopy(&res, memory_buffer + out_offset, sizeof(VTYPE));

  return res;
}

static const std::vector<int32_t> unsigned_test_offset() {
  static const int32_t kValues[] = {// value, offset
                                    -132 * KB, -21 * KB, 0, 19 * KB, 135 * KB};
  return std::vector<int32_t>(&kValues[0], &kValues[arraysize(kValues)]);
}

static const std::vector<int32_t> unsigned_test_offset_increment() {
  static const int32_t kValues[] = {-7, -6, -5, -4, -3, -2, -1, 0,
                                    1,  2,  3,  4,  5,  6,  7};
  return std::vector<int32_t>(&kValues[0], &kValues[arraysize(kValues)]);
}

TEST(LoadConstants) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope handles(isolate);

  int32_t refConstants[32];
  int32_t result[32];

  int32_t mask = 1;
  for (int i = 0; i < 32; i++) {
    refConstants[i] = ~(mask << i);
  }

  auto fn = [&refConstants](MacroAssembler& masm) {
    __ mv(a4, a0);
    for (int i = 0; i < 32; i++) {
      // Load constant.
      __ li(a5, Operand(refConstants[i]));
      __ Sw(a5, MemOperand(a4));
      __ AddWord(a4, a4, Operand(kSystemPointerSize));
    }
  };
  auto f = AssembleCode<FV>(isolate, fn);

  (void)f.Call(reinterpret_cast<int32_t>(result), 0, 0, 0, 0);
  // Check results.
  for (int i = 0; i < 32; i++) {
    CHECK(refConstants[i] == result[i]);
  }
}

TEST(LoadAddress) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope handles(isolate);

  MacroAssembler masm(isolate, v8::internal::CodeObjectRequired::kYes);
  Label to_jump, skip;
  __ mv(a4, a0);

  __ Branch(&skip);
  __ bind(&to_jump);
  __ nop();
  __ nop();
  __ jr(ra);
  __ nop();
  __ bind(&skip);
  __ li(a4,
        Operand(masm.jump_address(&to_jump),
                RelocInfo::INTERNAL_REFERENCE_ENCODED),
        ADDRESS_LOAD);
  int check_size = masm.InstructionsGeneratedSince(&skip);
  // NOTE (RISCV): current li generates 6 instructions, if the sequence is
  // changed, need to adjust the CHECK_EQ value too
  CHECK_EQ(2, check_size);
  __ jr(a4);
  __ nop();
  __ stop();
  __ stop();
  __ stop();
  __ stop();
  __ stop();

  CodeDesc desc;
  masm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<FV>::FromCode(isolate, *code);

  (void)f.Call(0, 0, 0, 0, 0);
  // Check results.
}

TEST(jump_tables4) {
  // Similar to test-assembler-mips jump_tables1, with extra test for branch
  // trampoline required before emission of the dd table (where trampolines are
  // blocked), and proper transition to long-branch mode.
  // Regression test for v8:4294.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler masm(isolate, v8::internal::CodeObjectRequired::kYes);

  const int kNumCases = 128;
  int32_t values[kNumCases];
  isolate->random_number_generator()->NextBytes(values, sizeof(values));
  Label labels[kNumCases];
  Label near_start, end, done;

  __ Push(ra);
  __ mv(a1, zero_reg);

  __ Branch(&end);
  __ bind(&near_start);

  // Generate slightly less than 32K instructions, which will soon require
  // trampoline for branch distance fixup.
  for (int i = 0; i < 32768 - 256; ++i) {
    __ addi(a1, a1, 1);
  }

  __ GenerateSwitchTable(a0, kNumCases,
                         [&labels](size_t i) { return labels + i; });

  for (int i = 0; i < kNumCases; ++i) {
    __ bind(&labels[i]);
    __ RV_li(a0, values[i]);
    __ Branch(&done);
  }

  __ bind(&done);
  __ Pop(ra);
  __ jr(ra);

  __ bind(&end);
  __ Branch(&near_start);

  CodeDesc desc;
  masm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code, std::cout);
#endif
  auto f = GeneratedCode<F1>::FromCode(isolate, *code);
  for (int i = 0; i < kNumCases; ++i) {
    int32_t res = reinterpret_cast<int32_t>(f.Call(i, 0, 0, 0, 0));
    // ::printf("f(%d) = %" PRId64 "\n", i, res);
    CHECK_EQ(values[i], res);
  }
}

TEST(jump_tables6) {
  // Similar to test-assembler-mips jump_tables1, with extra test for branch
  // trampoline required after emission of the dd table (where trampolines are
  // blocked). This test checks if number of really generated instructions is
  // greater than number of counted instructions from code, as we are expecting
  // generation of trampoline in this case (when number of kFillInstr
  // instructions is close to 32K)
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler masm(isolate, v8::internal::CodeObjectRequired::kYes);

  const int kSwitchTableCases = 40;

  const int kMaxBranchOffset = Assembler::kMaxBranchOffset;
  const int kTrampolineSlotsSize = Assembler::kTrampolineSlotsSize;
  const int kSwitchTablePrologueSize = MacroAssembler::kSwitchTablePrologueSize;

  const int kMaxOffsetForTrampolineStart =
      kMaxBranchOffset - 16 * kTrampolineSlotsSize;
  const int kFillInstr = (kMaxOffsetForTrampolineStart / kInstrSize) -
                         (kSwitchTablePrologueSize + 2 * kSwitchTableCases) -
                         20;

  int values[kSwitchTableCases];
  isolate->random_number_generator()->NextBytes(values, sizeof(values));
  Label labels[kSwitchTableCases];
  Label near_start, end, done;

  __ Push(ra);
  __ mv(a1, zero_reg);

  int offs1 = masm.pc_offset();
  int gen_insn = 0;

  __ Branch(&end);
  gen_insn += 1;
  __ bind(&near_start);

  // Generate slightly less than 32K instructions, which will soon require
  // trampoline for branch distance fixup.
  for (int i = 0; i < kFillInstr; ++i) {
    __ addi(a1, a1, 1);
  }
  gen_insn += kFillInstr;

  __ GenerateSwitchTable(a0, kSwitchTableCases,
                         [&labels](int i) { return labels + i; });
  gen_insn += (kSwitchTablePrologueSize + 1 * kSwitchTableCases);

  for (int i = 0; i < kSwitchTableCases; ++i) {
    __ bind(&labels[i]);
    __ li(a0, Operand(values[i]));
    __ Branch(&done);
  }
  gen_insn += 3 * kSwitchTableCases;

  // If offset from here to first branch instr is greater than max allowed
  // offset for trampoline ...
  CHECK_LT(kMaxOffsetForTrampolineStart, masm.pc_offset() - offs1);
  // ... number of generated instructions must be greater then "gen_insn",
  // as we are expecting trampoline generation
  CHECK_LT(gen_insn, (masm.pc_offset() - offs1) / kInstrSize);

  __ bind(&done);
  __ Pop(ra);
  __ jr(ra);
  __ nop();

  __ bind(&end);
  __ Branch(&near_start);

  CodeDesc desc;
  masm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code, std::cout);
#endif
  auto f = GeneratedCode<F1>::FromCode(isolate, *code);
  for (int i = 0; i < kSwitchTableCases; ++i) {
    int32_t res = reinterpret_cast<int32_t>(f.Call(i, 0, 0, 0, 0));
    ::printf("f(%d) = %" PRId32 "\n", i, res);
    CHECK_EQ(values[i], res);
  }
}

TEST(CalcScaledAddress) {
  CcTest::InitializeVM();
  struct TestCaseLsa {
    int32_t rt;
    int32_t rs;
    uint8_t sa;
    uint32_t expected_res;
  };

  struct TestCaseLsa tc[] = {// rt, rs, sa, expected_res
                             {0x4, 0x1, 1, 0x6},
                             {0x4, 0x1, 2, 0x8},
                             {0x4, 0x1, 3, 0xC},
                             {0x4, 0x1, 4, 0x14},
                             {0x4, 0x1, 5, 0x24},
                             {0x0, 0x1, 1, 0x2},
                             {0x0, 0x1, 2, 0x4},
                             {0x0, 0x1, 3, 0x8},
                             {0x0, 0x1, 4, 0x10},
                             {0x0, 0x1, 5, 0x20},
                             {0x4, 0x0, 1, 0x4},
                             {0x4, 0x0, 2, 0x4},
                             {0x4, 0x0, 3, 0x4},
                             {0x4, 0x0, 4, 0x4},
                             {0x4, 0x0, 5, 0x4},

                             // Shift overflow.
                             {0x4, INT32_MAX, 1, 0x2},
                             {0x4, INT32_MAX >> 1, 2, 0x0},
                             {0x4, INT32_MAX >> 2, 3, 0xFFFFFFFC},
                             {0x4, INT32_MAX >> 3, 4, 0xFFFFFFF4},
                             {0x4, INT32_MAX >> 4, 5, 0xFFFFFFE4},

                             // Signed addition overflow.
                             {INT32_MAX - 1, 0x1, 1, 0x80000000},
                             {INT32_MAX - 3, 0x1, 2, 0x80000000},
                             {INT32_MAX - 7, 0x1, 3, 0x80000000},
                             {INT32_MAX - 15, 0x1, 4, 0x80000000},
                             {INT32_MAX - 31, 0x1, 5, 0x80000000},

                             // Addition overflow.
                             {-2, 0x1, 1, 0x0},
                             {-4, 0x1, 2, 0x0},
                             {-8, 0x1, 3, 0x0},
                             {-16, 0x1, 4, 0x0},
                             {-32, 0x1, 5, 0x0}};

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseLsa);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    uint32_t res = run_CalcScaledAddress(tc[i].rt, tc[i].rs, tc[i].sa);
    CHECK_EQ(tc[i].expected_res, res);
  }
}

static const std::vector<uint32_t> cvt_trunc_uint32_test_values() {
  static const uint32_t kValues[] = {0x00000000, 0x00000001, 0x00FFFF00,
                                     0x7FFFFFFF, 0x80000000, 0x80000001,
                                     0x80FFFF00, 0x8FFFFFFF};
  return std::vector<uint32_t>(&kValues[0], &kValues[arraysize(kValues)]);
}

static const std::vector<int32_t> cvt_trunc_int32_test_values() {
  static const int32_t kValues[] = {
      static_cast<int32_t>(0x00000000), static_cast<int32_t>(0x00000001),
      static_cast<int32_t>(0x00FFFF00), static_cast<int32_t>(0x7FFFFFFF),
      static_cast<int32_t>(0x80000000), static_cast<int32_t>(0x80000001),
      static_cast<int32_t>(0x80FFFF00), static_cast<int32_t>(0x8FFFFFFF),
      static_cast<int32_t>(0xFFFFFFFF)};
  return std::vector<int32_t>(&kValues[0], &kValues[arraysize(kValues)]);
}

#define FOR_INPUTS3(ctype, var, test_vector)    \
  std::vector<ctype> var##_vec = test_vector(); \
  for (ctype var : var##_vec)

#define FOR_INT32_INPUTS3(var, test_vector) \
  FOR_INPUTS3(int32_t, var, test_vector)
#define FOR_INT64_INPUTS3(var, test_vector) \
  FOR_INPUTS3(int64_t, var, test_vector)
#define FOR_UINT32_INPUTS3(var, test_vector) \
  FOR_INPUTS3(uint32_t, var, test_vector)
#define FOR_UINT64_INPUTS3(var, test_vector) \
  FOR_INPUTS3(uint64_t, var, test_vector)

#define FOR_TWO_INPUTS(ctype, var1, var2, test_vector)      \
  std::vector<ctype> var##_vec = test_vector();             \
  std::vector<ctype>::iterator var1;                        \
  std::vector<ctype>::reverse_iterator var2;                \
  for (var1 = var##_vec.begin(), var2 = var##_vec.rbegin(); \
       var1 != var##_vec.end(); ++var1, ++var2)

#define FOR_INT32_TWO_INPUTS(var1, var2, test_vector) \
  FOR_TWO_INPUTS(int32_t, var1, var2, test_vector)

TEST(Cvt_s_uw_Trunc_uw_s) {
  CcTest::InitializeVM();
  auto fn = [](MacroAssembler& masm) {
    __ Cvt_s_uw(fa0, a0);
    __ Trunc_uw_s(a0, fa0);
  };
  FOR_UINT32_INPUTS3(i, cvt_trunc_uint32_test_values) {
    // some integers cannot be represented precisely in float,  input may
    // not directly match the return value of GenAndRunTest
    CHECK_EQ(static_cast<uint32_t>(static_cast<float>(i)),
             GenAndRunTest<uint32_t>(i, fn));
  }
}

TEST(cvt_d_w_Trunc_w_d) {
  CcTest::InitializeVM();
  auto fn = [](MacroAssembler& masm) {
    __ fcvt_d_w(fa0, a0);
    __ Trunc_w_d(a0, fa0);
  };
  FOR_INT32_INPUTS3(i, cvt_trunc_int32_test_values) {
    CHECK_EQ(static_cast<int32_t>(static_cast<double>(i)),
             GenAndRunTest<int32_t>(i, fn));
  }
}

static const std::vector<int32_t> overflow_int32_test_values() {
  static const int32_t kValues[] = {
      static_cast<int32_t>(0xF0000000), static_cast<int32_t>(0x00000001),
      static_cast<int32_t>(0xFF000000), static_cast<int32_t>(0x0F000011),
      static_cast<int32_t>(0x00F00100), static_cast<int32_t>(0x991234AB),
      static_cast<int32_t>(0xB0FFFF0F), static_cast<int32_t>(0x6FFFFFFF),
      static_cast<int32_t>(0xFFFFFFFF)};
  return std::vector<int32_t>(&kValues[0], &kValues[arraysize(kValues)]);
}

TEST(OverflowInstructions) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope handles(isolate);

  struct T {
    int32_t lhs;
    int32_t rhs;
    int32_t output_add;
    int32_t output_add2;
    int32_t output_sub;
    int32_t output_sub2;
    int32_t output_mul;
    int32_t output_mul2;
    int32_t overflow_add;
    int32_t overflow_add2;
    int32_t overflow_sub;
    int32_t overflow_sub2;
    int32_t overflow_mul;
    int32_t overflow_mul2;
  } t;

  FOR_INT32_INPUTS3(i, overflow_int32_test_values) {
    FOR_INT32_INPUTS3(j, overflow_int32_test_values) {
      auto ii = i;
      auto jj = j;
      int32_t expected_add, expected_sub;
      int32_t ii32 = static_cast<int32_t>(ii);
      int32_t jj32 = static_cast<int32_t>(jj);
      int32_t expected_mul;
      int32_t expected_add_ovf, expected_sub_ovf, expected_mul_ovf;

      auto fn = [](MacroAssembler& masm) {
        __ Lw(t0, MemOperand(a0, offsetof(T, lhs)));
        __ Lw(t1, MemOperand(a0, offsetof(T, rhs)));

        __ AddOverflow(t2, t0, Operand(t1), a1);
        __ Sw(t2, MemOperand(a0, offsetof(T, output_add)));
        __ Sw(a1, MemOperand(a0, offsetof(T, overflow_add)));
        __ mv(a1, zero_reg);
        __ AddOverflow(t0, t0, Operand(t1), a1);
        __ Sw(t0, MemOperand(a0, offsetof(T, output_add2)));
        __ Sw(a1, MemOperand(a0, offsetof(T, overflow_add2)));

        __ Lw(t0, MemOperand(a0, offsetof(T, lhs)));
        __ Lw(t1, MemOperand(a0, offsetof(T, rhs)));

        __ SubOverflow(t2, t0, Operand(t1), a1);
        __ Sw(t2, MemOperand(a0, offsetof(T, output_sub)));
        __ Sw(a1, MemOperand(a0, offsetof(T, overflow_sub)));
        __ mv(a1, zero_reg);
        __ SubOverflow(t0, t0, Operand(t1), a1);
        __ Sw(t0, MemOperand(a0, offsetof(T, output_sub2)));
        __ Sw(a1, MemOperand(a0, offsetof(T, overflow_sub2)));

        __ Lw(t0, MemOperand(a0, offsetof(T, lhs)));
        __ Lw(t1, MemOperand(a0, offsetof(T, rhs)));
        __ MulOverflow32(t2, t0, Operand(t1), a1);
        __ Sw(t2, MemOperand(a0, offsetof(T, output_mul)));
        __ Sw(a1, MemOperand(a0, offsetof(T, overflow_mul)));
        __ mv(a1, zero_reg);
        __ MulOverflow32(t0, t0, Operand(t1), a1);
        __ Sw(t0, MemOperand(a0, offsetof(T, output_mul2)));
        __ Sw(a1, MemOperand(a0, offsetof(T, overflow_mul2)));
      };
      auto f = AssembleCode<F3>(isolate, fn);

      t.lhs = ii;
      t.rhs = jj;
      f.Call(&t, 0, 0, 0, 0);

      expected_add_ovf = base::bits::SignedAddOverflow32(ii, jj, &expected_add);
      expected_sub_ovf = base::bits::SignedSubOverflow32(ii, jj, &expected_sub);
      expected_mul_ovf =
          base::bits::SignedMulOverflow32(ii32, jj32, &expected_mul);

      CHECK_EQ(expected_add_ovf, t.overflow_add < 0);
      CHECK_EQ(expected_sub_ovf, t.overflow_sub < 0);
      CHECK_EQ(expected_mul_ovf, t.overflow_mul != 0);

      CHECK_EQ(t.overflow_add, t.overflow_add2);
      CHECK_EQ(t.overflow_sub, t.overflow_sub2);
      CHECK_EQ(t.overflow_mul, t.overflow_mul2);

      CHECK_EQ(expected_add, t.output_add);
      CHECK_EQ(expected_add, t.output_add2);
      CHECK_EQ(expected_sub, t.output_sub);
      CHECK_EQ(expected_sub, t.output_sub2);
      if (!expected_mul_ovf) {
        CHECK_EQ(expected_mul, t.output_mul);
        CHECK_EQ(expected_mul, t.output_mul2);
      }
    }
  }
}

TEST(min_max_nan) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct TestFloat {
    double a;
    double b;
    double c;
    double d;
    float e;
    float f;
    float g;
    float h;
  } test;

  const int kTableLength = 13;

  double inputsa[kTableLength] = {2.0,   3.0,    -0.0,  0.0,    42.0,
                                  inf_d, minf_d, inf_d, qnan_d, 3.0,
                                  inf_d, qnan_d, qnan_d};
  double inputsb[kTableLength] = {3.0,    2.0,   0.0,    -0.0, inf_d,
                                  42.0,   inf_d, minf_d, 3.0,  qnan_d,
                                  qnan_d, inf_d, qnan_d};
  double outputsdmin[kTableLength] = {2.0,    2.0,    -0.0,   -0.0,   42.0,
                                      42.0,   minf_d, minf_d, qnan_d, qnan_d,
                                      qnan_d, qnan_d, qnan_d};
  double outputsdmax[kTableLength] = {3.0,    3.0,    0.0,   0.0,    inf_d,
                                      inf_d,  inf_d,  inf_d, qnan_d, qnan_d,
                                      qnan_d, qnan_d, qnan_d};

  float inputse[kTableLength] = {2.0,   3.0,    -0.0,  0.0,    42.0,
                                 inf_f, minf_f, inf_f, qnan_f, 3.0,
                                 inf_f, qnan_f, qnan_f};
  float inputsf[kTableLength] = {3.0,    2.0,   0.0,    -0.0, inf_f,
                                 42.0,   inf_f, minf_f, 3.0,  qnan_f,
                                 qnan_f, inf_f, qnan_f};
  float outputsfmin[kTableLength] = {2.0,    2.0,    -0.0,   -0.0,   42.0,
                                     42.0,   minf_f, minf_f, qnan_f, qnan_f,
                                     qnan_f, qnan_f, qnan_f};
  float outputsfmax[kTableLength] = {3.0,    3.0,    0.0,   0.0,    inf_f,
                                     inf_f,  inf_f,  inf_f, qnan_f, qnan_f,
                                     qnan_f, qnan_f, qnan_f};

  auto fn = [](MacroAssembler& masm) {
    __ push(s6);
    __ InitializeRootRegister();
    __ LoadDouble(fa3, MemOperand(a0, offsetof(TestFloat, a)));
    __ LoadDouble(fa4, MemOperand(a0, offsetof(TestFloat, b)));
    __ LoadFloat(fa1, MemOperand(a0, offsetof(TestFloat, e)));
    __ LoadFloat(fa2, MemOperand(a0, offsetof(TestFloat, f)));
    __ Float64Min(fa5, fa3, fa4);
    __ Float64Max(fa6, fa3, fa4);
    __ Float32Min(fa7, fa1, fa2);
    __ Float32Max(fa0, fa1, fa2);
    __ StoreDouble(fa5, MemOperand(a0, offsetof(TestFloat, c)));
    __ StoreDouble(fa6, MemOperand(a0, offsetof(TestFloat, d)));
    __ StoreFloat(fa7, MemOperand(a0, offsetof(TestFloat, g)));
    __ StoreFloat(fa0, MemOperand(a0, offsetof(TestFloat, h)));
    __ pop(s6);
  };
  auto f = AssembleCode<F3>(isolate, fn);

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

TEST(Ulh) {
  CcTest::InitializeVM();

  static const int kBufferSize = 300 * KB;
  char memory_buffer[kBufferSize];
  char* buffer_middle = memory_buffer + (kBufferSize / 2);

  auto fn1 = [](MacroAssembler& masm, int32_t in_offset, int32_t out_offset) {
    __ Ulh(t0, MemOperand(a0, in_offset));
    __ Ush(t0, MemOperand(a0, out_offset));
  };

  auto fn2 = [](MacroAssembler& masm, int32_t in_offset, int32_t out_offset) {
    __ mv(t0, a0);
    __ Ulh(a0, MemOperand(a0, in_offset));
    __ Ush(a0, MemOperand(t0, out_offset));
  };

  auto fn3 = [](MacroAssembler& masm, int32_t in_offset, int32_t out_offset) {
    __ mv(t0, a0);
    __ Ulhu(a0, MemOperand(a0, in_offset));
    __ Ush(a0, MemOperand(t0, out_offset));
  };

  auto fn4 = [](MacroAssembler& masm, int32_t in_offset, int32_t out_offset) {
    __ Ulhu(t0, MemOperand(a0, in_offset));
    __ Ush(t0, MemOperand(a0, out_offset));
  };

  FOR_UINT16_INPUTS(i) {
    FOR_INT32_TWO_INPUTS(j1, j2, unsigned_test_offset) {
      FOR_INT32_TWO_INPUTS(k1, k2, unsigned_test_offset_increment) {
        auto value = i;
        int32_t in_offset = *j1 + *k1;
        int32_t out_offset = *j2 + *k2;
        CHECK_EQ(value, run_Unaligned(buffer_middle, in_offset, out_offset,
                                      value, fn1));

        // test when loaded value overwrites base-register of load address
        CHECK_EQ(value, run_Unaligned(buffer_middle, in_offset, out_offset,
                                      value, fn2));

        // test when loaded value overwrites base-register of load address
        CHECK_EQ(value, run_Unaligned(buffer_middle, in_offset, out_offset,
                                      value, fn3));

        CHECK_EQ(value, run_Unaligned(buffer_middle, in_offset, out_offset,
                                      value, fn4));
      }
    }
  }
}

TEST(Ulh_bitextension) {
  CcTest::InitializeVM();

  static const int kBufferSize = 300 * KB;
  char memory_buffer[kBufferSize];
  char* buffer_middle = memory_buffer + (kBufferSize / 2);

  auto fn = [](MacroAssembler& masm, int32_t in_offset, int32_t out_offset) {
    Label success, fail, end, different;
    __ Ulh(t0, MemOperand(a0, in_offset));
    __ Ulhu(t1, MemOperand(a0, in_offset));
    __ Branch(&different, ne, t0, Operand(t1));

    // If signed and unsigned values are same, check
    // the upper bits to see if they are zero
    __ srai(t0, t0, 15);
    __ Branch(&success, eq, t0, Operand(zero_reg));
    __ Branch(&fail);

    // If signed and unsigned values are different,
    // check that the upper bits are complementary
    __ bind(&different);
    __ srai(t1, t1, 15);
    __ Branch(&fail, ne, t1, Operand(1));
    __ srai(t0, t0, 15);
    __ addi(t0, t0, 1);
    __ Branch(&fail, ne, t0, Operand(zero_reg));
    // Fall through to success

    __ bind(&success);
    __ Ulh(t0, MemOperand(a0, in_offset));
    __ Ush(t0, MemOperand(a0, out_offset));
    __ Branch(&end);
    __ bind(&fail);
    __ Ush(zero_reg, MemOperand(a0, out_offset));
    __ bind(&end);
  };

  FOR_UINT16_INPUTS(i) {
    FOR_INT32_TWO_INPUTS(j1, j2, unsigned_test_offset) {
      FOR_INT32_TWO_INPUTS(k1, k2, unsigned_test_offset_increment) {
        auto value = i;
        int32_t in_offset = *j1 + *k1;
        int32_t out_offset = *j2 + *k2;
        CHECK_EQ(value, run_Unaligned(buffer_middle, in_offset, out_offset,
                                      value, fn));
      }
    }
  }
}

TEST(Ulw) {
  CcTest::InitializeVM();

  static const int kBufferSize = 300 * KB;
  char memory_buffer[kBufferSize];
  char* buffer_middle = memory_buffer + (kBufferSize / 2);

  auto fn_1 = [](MacroAssembler& masm, int32_t in_offset, int32_t out_offset) {
    __ Ulw(t0, MemOperand(a0, in_offset));
    __ Usw(t0, MemOperand(a0, out_offset));
  };

  auto fn_2 = [](MacroAssembler& masm, int32_t in_offset, int32_t out_offset) {
    __ mv(t0, a0);
    __ Ulw(a0, MemOperand(a0, in_offset));
    __ Usw(a0, MemOperand(t0, out_offset));
  };

  FOR_UINT32_INPUTS(i) {
    FOR_INT32_TWO_INPUTS(j1, j2, unsigned_test_offset) {
      FOR_INT32_TWO_INPUTS(k1, k2, unsigned_test_offset_increment) {
        auto value = i;
        int32_t in_offset = *j1 + *k1;
        int32_t out_offset = *j2 + *k2;

        CHECK_EQ(value, run_Unaligned(buffer_middle, in_offset, out_offset,
                                      value, fn_1));
        // test when loaded value overwrites base-register of load address
        CHECK_EQ(value, run_Unaligned(buffer_middle, in_offset, out_offset,
                                      value, fn_2));
      }
    }
  }
}

TEST(ULoadFloat) {
  auto fn = [](MacroAssembler& masm, int32_t in_offset, int32_t out_offset) {
    __ ULoadFloat(fa0, MemOperand(a0, in_offset), t0);
    __ UStoreFloat(fa0, MemOperand(a0, out_offset), t0);
  };
  CcTest::InitializeVM();

  static const int kBufferSize = 300 * KB;
  char memory_buffer[kBufferSize];
  char* buffer_middle = memory_buffer + (kBufferSize / 2);

  FOR_FLOAT32_INPUTS(i) {
    // skip nan because CHECK_EQ cannot handle NaN
    if (std::isnan(i)) continue;
    FOR_INT32_TWO_INPUTS(j1, j2, unsigned_test_offset) {
      FOR_INT32_TWO_INPUTS(k1, k2, unsigned_test_offset_increment) {
        auto value = i;
        int32_t in_offset = *j1 + *k1;
        int32_t out_offset = *j2 + *k2;
        CHECK_EQ(value, run_Unaligned(buffer_middle, in_offset, out_offset,
                                      value, fn));
      }
    }
  }
}

TEST(ULoadDouble) {
  CcTest::InitializeVM();

  static const int kBufferSize = 300 * KB;
  char memory_buffer[kBufferSize];
  char* buffer_middle = memory_buffer + (kBufferSize / 2);

  auto fn = [](MacroAssembler& masm, int32_t in_offset, int32_t out_offset) {
    __ ULoadDouble(fa0, MemOperand(a0, in_offset), t0);
    __ UStoreDouble(fa0, MemOperand(a0, out_offset), t0);
  };

  FOR_FLOAT64_INPUTS(i) {
    // skip nan because CHECK_EQ cannot handle NaN
    if (std::isnan(i)) continue;
    FOR_INT32_TWO_INPUTS(j1, j2, unsigned_test_offset) {
      FOR_INT32_TWO_INPUTS(k1, k2, unsigned_test_offset_increment) {
        auto value = i;
        int32_t in_offset = *j1 + *k1;
        int32_t out_offset = *j2 + *k2;
        CHECK_EQ(value, run_Unaligned(buffer_middle, in_offset, out_offset,
                                      value, fn));
      }
    }
  }
}

TEST(Sltu) {
  CcTest::InitializeVM();

  FOR_UINT32_INPUTS(i) {
    FOR_UINT32_INPUTS(j) {
      // compare against immediate value
      auto fn_1 = [j](MacroAssembler& masm) { __ Sltu(a0, a0, Operand(j)); };
      CHECK_EQ(i < j, GenAndRunTest<int32_t>(i, fn_1));
      // compare against registers
      auto fn_2 = [](MacroAssembler& masm) { __ Sltu(a0, a0, a1); };
      CHECK_EQ(i < j, GenAndRunTest<int32_t>(i, j, fn_2));
    }
  }
}

template <typename T, typename Inputs, typename Results>
static void GenerateMacroFloat32MinMax(MacroAssembler& masm) {
  T a = T::from_code(5);  // ft5
  T b = T::from_code(6);  // ft6
  T c = T::from_code(7);  // ft7

#define FLOAT_MIN_MAX(fminmax, res, x, y, res_field)        \
  __ LoadFloat(x, MemOperand(a0, offsetof(Inputs, src1_))); \
  __ LoadFloat(y, MemOperand(a0, offsetof(Inputs, src2_))); \
  __ fminmax(res, x, y);                                    \
  __ StoreFloat(res, MemOperand(a1, offsetof(Results, res_field)))

  // a = min(b, c);
  FLOAT_MIN_MAX(Float32Min, a, b, c, min_abc_);
  // a = min(a, b);
  FLOAT_MIN_MAX(Float32Min, a, a, b, min_aab_);
  // a = min(b, a);
  FLOAT_MIN_MAX(Float32Min, a, b, a, min_aba_);

  // a = max(b, c);
  FLOAT_MIN_MAX(Float32Max, a, b, c, max_abc_);
  // a = max(a, b);
  FLOAT_MIN_MAX(Float32Max, a, a, b, max_aab_);
  // a = max(b, a);
  FLOAT_MIN_MAX(Float32Max, a, b, a, max_aba_);

#undef FLOAT_MIN_MAX
}

TEST(macro_float_minmax_f32) {
  // Test the Float32Min and Float32Max macros.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct Inputs {
    float src1_;
    float src2_;
  };

  struct Results {
    // Check all register aliasing possibilities in order to exercise all
    // code-paths in the macro masm.
    float min_abc_;
    float min_aab_;
    float min_aba_;
    float max_abc_;
    float max_aab_;
    float max_aba_;
  };

  auto f = AssembleCode<F4>(
      isolate, GenerateMacroFloat32MinMax<FPURegister, Inputs, Results>);

#define CHECK_MINMAX(src1, src2, min, max)                                \
  do {                                                                    \
    Inputs inputs = {src1, src2};                                         \
    Results results;                                                      \
    f.Call(&inputs, &results, 0, 0, 0);                                   \
    CHECK_EQ(base::bit_cast<uint32_t>(min),                               \
             base::bit_cast<uint32_t>(results.min_abc_));                 \
    CHECK_EQ(base::bit_cast<uint32_t>(min),                               \
             base::bit_cast<uint32_t>(results.min_aab_));                 \
    CHECK_EQ(base::bit_cast<uint32_t>(min),                               \
             base::bit_cast<uint32_t>(results.min_aba_));                 \
    CHECK_EQ(base::bit_cast<uint32_t>(max),                               \
             base::bit_cast<uint32_t>(results.max_abc_));                 \
    CHECK_EQ(base::bit_cast<uint32_t>(max),                               \
             base::bit_cast<uint32_t>(results.max_aab_));                 \
    CHECK_EQ(base::bit_cast<uint32_t>(max),                               \
             base::bit_cast<uint32_t>(                                    \
                 results.max_aba_)); /* Use a base::bit_cast to correctly \
                                  identify -0.0 and NaNs. */              \
  } while (0)

  float nan_a = std::numeric_limits<float>::quiet_NaN();
  float nan_b = std::numeric_limits<float>::quiet_NaN();

  CHECK_MINMAX(1.0f, -1.0f, -1.0f, 1.0f);
  CHECK_MINMAX(-1.0f, 1.0f, -1.0f, 1
```