Response:
The user wants a summary of the provided C++ code. I need to identify the purpose of the code and its functionalities.

The code defines a series of unit tests for the instruction selector in the V8 compiler for the ARM architecture. It tests various ARM instructions, including:

- Data processing instructions (arithmetic and logical operations).
- Floating-point arithmetic instructions.
- Data processing instructions with overflow.
- Shift operations.

The tests cover different operand types (registers and immediates) and combinations with shift operations. They also test branching based on the results of these operations.

Based on the request, I should provide the following:
1. List the functionalities of the code.
2. Check if the filename ends with `.tq`.
3. Determine if the code relates to JavaScript.
4. Provide JavaScript examples if applicable.
5. Provide code logic reasoning with input/output examples.
6. Give examples of common programming errors if applicable.
7. Summarize the functionalities for part 1.
这是V8编译器中针对ARM架构的指令选择器单元测试的一部分。其主要功能是测试指令选择器是否能够为特定的中间表示（IR）节点正确地选择和生成相应的ARM机器指令。

具体来说，这段代码测试了以下功能：

1. **数据处理指令 (Data Processing Instructions - DPI):**  测试了 `AND`, `OR`, `XOR`, `ADD`, `SUB` 等基本的32位整数运算指令。
    *   测试了这些指令在操作数是寄存器、立即数以及带移位操作的情况下的指令选择。
    *   测试了基于这些指令结果进行条件分支的情况。
    *   测试了基于这些指令结果是否为零进行条件分支的情况。

2. **浮点运算指令 (Floating Point Arithmetic Instructions - FAI):** 测试了 `Float32Add`, `Float64Add`, `Float32Sub`, `Float64Sub`, `Float32Mul`, `Float64Mul`, `Float32Div`, `Float64Div` 等浮点运算指令。
    *   测试了这些指令在操作数是寄存器的情况下的指令选择。

3. **带溢出的数据处理指令 (Data Processing Instructions with Overflow - ODPI):** 测试了 `Int32AddWithOverflow` 和 `Int32SubWithOverflow` 这两个可能产生溢出的整数运算指令。
    *   测试了这些指令在操作数是寄存器、立即数以及带移位操作的情况下的指令选择。
    *   测试了如何获取运算结果和溢出标志。

4. **移位操作 (Shifts):**  定义了 `SAR` (算术右移), `SHL` (逻辑左移), `SHR` (逻辑右移), `ROR` (循环右移) 等移位操作。
    *   测试了这些移位操作在移位量是立即数或寄存器的情况下的指令选择。
    *   这些移位操作被用作数据处理指令的操作数的一部分进行测试。

**关于文件类型:**

`v8/test/unittests/compiler/arm/instruction-selector-arm-unittest.cc`  以 `.cc` 结尾，所以它是一个 **C++** 源代码文件，而不是 Torque 源代码。

**与JavaScript的关系:**

这段代码是V8 JavaScript引擎的组成部分。指令选择器是编译器后端的一个重要阶段，它将高级的、平台无关的中间表示转换为特定架构的机器码，例如ARM。因此，这段代码的正确性直接影响到JavaScript代码在ARM架构上的执行效率和正确性。

**JavaScript举例说明:**

虽然这段代码本身是C++，但它测试的是为了支持JavaScript的整数和浮点数运算而生成的机器码。例如，`InstructionSelectorDPITest` 测试的 `Int32Add` 对应于 JavaScript 中的加法操作：

```javascript
let a = 10;
let b = 20;
let sum = a + b; // 这里的 '+' 操作在底层可能就涉及到 Int32Add 指令
```

`InstructionSelectorFAITest` 测试的 `Float64Add` 对应于 JavaScript 中的浮点数加法操作：

```javascript
let x = 3.14;
let y = 2.71;
let result = x + y; // 这里的 '+' 操作在底层可能就涉及到 Float64Add 指令
```

`InstructionSelectorODPITest` 测试的带溢出的加法，虽然 JavaScript 的标准加法运算符不会直接暴露溢出标志，但在某些特定的位操作或者内部实现中可能会用到：

```javascript
// JavaScript 中没有直接的溢出标志，但可以进行位运算
let maxInt = 2147483647;
let overflow = maxInt + 1; // 结果会回绕，但不会抛出溢出错误
```

**代码逻辑推理 (假设输入与输出):**

以 `TEST_P(InstructionSelectorDPITest, Parameters)` 中的 `Int32Add` 为例：

**假设输入:**

*   `m.Parameter(0)` 代表一个值为 5 的寄存器。
*   `m.Parameter(1)` 代表一个值为 10 的寄存器。

**代码逻辑:**

`m.Return((m.*dpi.constructor)(m.Parameter(0), m.Parameter(1)));`  这行代码会生成一个表示 `Int32Add` 操作的 IR 节点，其操作数是上述两个寄存器。指令选择器需要将这个 IR 节点转换为 ARM 的 `ADD` 指令。

**预期输出:**

生成的 ARM 指令应该是类似于 `ADD Rd, Rn, Rm` 的形式，其中 `Rd` 是存放结果的寄存器，`Rn` 和 `Rm` 分别是存放操作数的寄存器。单元测试会验证生成的指令的 `arch_opcode()` 是否为 `kArmAdd`，`addressing_mode()` 是否为 `kMode_Operand2_R` (表示操作数是寄存器)。

**涉及用户常见的编程错误 (可能相关):**

虽然这段代码主要测试编译器内部的逻辑，但它所覆盖的指令与用户可能遇到的编程错误间接相关。例如：

*   **整数溢出:**  `InstructionSelectorODPITest` 测试了带溢出的指令。用户在进行大整数运算时，如果不注意数据类型范围，可能会发生溢出，导致程序行为不符合预期。虽然 JavaScript 的 Number 类型可以表示较大的整数，但在进行位运算时，可能会涉及到 32 位整数，此时就可能发生溢出。

    ```javascript
    let a = 2147483647;
    let b = 1;
    let sum = a + b; // JavaScript 中结果会变成 -2147483648 (回绕)
    ```

*   **浮点数精度问题:** `InstructionSelectorFAITest` 测试了浮点运算。用户在使用浮点数进行计算时，可能会遇到精度丢失的问题，因为浮点数的表示是近似的。

    ```javascript
    let a = 0.1;
    let b = 0.2;
    let sum = a + b;
    console.log(sum); // 输出结果可能不是精确的 0.3
    ```

**功能归纳 (第1部分):**

这段代码（第1部分）的主要功能是测试 V8 编译器中 ARM 架构的指令选择器在处理基本的 **32位整数数据处理指令**（如 AND, OR, XOR, ADD, SUB）、**浮点数算术指令** (如加减乘除) 以及相关的 **移位操作** 时的正确性。它验证了对于不同的操作数类型（寄存器、立即数）和操作数组合（带移位），指令选择器能够生成预期的 ARM 机器指令。此外，它还测试了基于这些数据处理指令的结果进行条件分支的指令选择。

### 提示词
```
这是目录为v8/test/unittests/compiler/arm/instruction-selector-arm-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler/arm/instruction-selector-arm-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <limits>

#include "test/unittests/compiler/backend/instruction-selector-unittest.h"

#include "src/objects/objects-inl.h"

namespace v8 {
namespace internal {
namespace compiler {

namespace {

using Constructor = Node* (RawMachineAssembler::*)(Node*, Node*);

// Data processing instructions.
struct DPI {
  Constructor constructor;
  const char* constructor_name;
  ArchOpcode arch_opcode;
  ArchOpcode reverse_arch_opcode;
  ArchOpcode test_arch_opcode;
};


std::ostream& operator<<(std::ostream& os, const DPI& dpi) {
  return os << dpi.constructor_name;
}


const DPI kDPIs[] = {
    {&RawMachineAssembler::Word32And, "Word32And", kArmAnd, kArmAnd, kArmTst},
    {&RawMachineAssembler::Word32Or, "Word32Or", kArmOrr, kArmOrr, kArmOrr},
    {&RawMachineAssembler::Word32Xor, "Word32Xor", kArmEor, kArmEor, kArmTeq},
    {&RawMachineAssembler::Int32Add, "Int32Add", kArmAdd, kArmAdd, kArmCmn},
    {&RawMachineAssembler::Int32Sub, "Int32Sub", kArmSub, kArmRsb, kArmCmp}};


// Floating point arithmetic instructions.
struct FAI {
  Constructor constructor;
  const char* constructor_name;
  MachineType machine_type;
  ArchOpcode arch_opcode;
};


std::ostream& operator<<(std::ostream& os, const FAI& fai) {
  return os << fai.constructor_name;
}


const FAI kFAIs[] = {{&RawMachineAssembler::Float32Add, "Float32Add",
                      MachineType::Float32(), kArmVaddF32},
                     {&RawMachineAssembler::Float64Add, "Float64Add",
                      MachineType::Float64(), kArmVaddF64},
                     {&RawMachineAssembler::Float32Sub, "Float32Sub",
                      MachineType::Float32(), kArmVsubF32},
                     {&RawMachineAssembler::Float64Sub, "Float64Sub",
                      MachineType::Float64(), kArmVsubF64},
                     {&RawMachineAssembler::Float32Mul, "Float32Mul",
                      MachineType::Float32(), kArmVmulF32},
                     {&RawMachineAssembler::Float64Mul, "Float64Mul",
                      MachineType::Float64(), kArmVmulF64},
                     {&RawMachineAssembler::Float32Div, "Float32Div",
                      MachineType::Float32(), kArmVdivF32},
                     {&RawMachineAssembler::Float64Div, "Float64Div",
                      MachineType::Float64(), kArmVdivF64}};


// Data processing instructions with overflow.
struct ODPI {
  Constructor constructor;
  const char* constructor_name;
  ArchOpcode arch_opcode;
  ArchOpcode reverse_arch_opcode;
};


std::ostream& operator<<(std::ostream& os, const ODPI& odpi) {
  return os << odpi.constructor_name;
}


const ODPI kODPIs[] = {{&RawMachineAssembler::Int32AddWithOverflow,
                        "Int32AddWithOverflow", kArmAdd, kArmAdd},
                       {&RawMachineAssembler::Int32SubWithOverflow,
                        "Int32SubWithOverflow", kArmSub, kArmRsb}};


// Shifts.
struct Shift {
  Constructor constructor;
  const char* constructor_name;
  int32_t i_low;          // lowest possible immediate
  int32_t i_high;         // highest possible immediate
  AddressingMode i_mode;  // Operand2_R_<shift>_I
  AddressingMode r_mode;  // Operand2_R_<shift>_R
};


std::ostream& operator<<(std::ostream& os, const Shift& shift) {
  return os << shift.constructor_name;
}


const Shift kShifts[] = {{&RawMachineAssembler::Word32Sar, "Word32Sar", 1, 32,
                          kMode_Operand2_R_ASR_I, kMode_Operand2_R_ASR_R},
                         {&RawMachineAssembler::Word32Shl, "Word32Shl", 0, 31,
                          kMode_Operand2_R_LSL_I, kMode_Operand2_R_LSL_R},
                         {&RawMachineAssembler::Word32Shr, "Word32Shr", 1, 32,
                          kMode_Operand2_R_LSR_I, kMode_Operand2_R_LSR_R},
                         {&RawMachineAssembler::Word32Ror, "Word32Ror", 1, 31,
                          kMode_Operand2_R_ROR_I, kMode_Operand2_R_ROR_R}};


// Immediates (random subset).
const int32_t kImmediates[] = {
    std::numeric_limits<int32_t>::min(), -2147483617, -2147483606, -2113929216,
    -2080374784, -1996488704, -1879048192, -1459617792, -1358954496,
    -1342177265, -1275068414, -1073741818, -1073741777, -855638016, -805306368,
    -402653184, -268435444, -16777216, 0, 35, 61, 105, 116, 171, 245, 255, 692,
    1216, 1248, 1520, 1600, 1888, 3744, 4080, 5888, 8384, 9344, 9472, 9792,
    13312, 15040, 15360, 20736, 22272, 23296, 32000, 33536, 37120, 45824, 47872,
    56320, 59392, 65280, 72704, 101376, 147456, 161792, 164864, 167936, 173056,
    195584, 209920, 212992, 356352, 655360, 704512, 716800, 851968, 901120,
    1044480, 1523712, 2572288, 3211264, 3588096, 3833856, 3866624, 4325376,
    5177344, 6488064, 7012352, 7471104, 14090240, 16711680, 19398656, 22282240,
    28573696, 30408704, 30670848, 43253760, 54525952, 55312384, 56623104,
    68157440, 115343360, 131072000, 187695104, 188743680, 195035136, 197132288,
    203423744, 218103808, 267386880, 268435470, 285212672, 402653185, 415236096,
    595591168, 603979776, 603979778, 629145600, 1073741835, 1073741855,
    1073741861, 1073741884, 1157627904, 1476395008, 1476395010, 1610612741,
    2030043136, 2080374785, 2097152000};

}  // namespace


// -----------------------------------------------------------------------------
// Data processing instructions.

using InstructionSelectorDPITest = InstructionSelectorTestWithParam<DPI>;

TEST_P(InstructionSelectorDPITest, Parameters) {
  const DPI dpi = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  m.Return((m.*dpi.constructor)(m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kMode_Operand2_R, s[0]->addressing_mode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}


TEST_P(InstructionSelectorDPITest, Immediate) {
  const DPI dpi = GetParam();
  TRACED_FOREACH(int32_t, imm, kImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return((m.*dpi.constructor)(m.Parameter(0), m.Int32Constant(imm)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_I, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  TRACED_FOREACH(int32_t, imm, kImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return((m.*dpi.constructor)(m.Int32Constant(imm), m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(dpi.reverse_arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_I, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}


TEST_P(InstructionSelectorDPITest, ShiftByParameter) {
  const DPI dpi = GetParam();
  TRACED_FOREACH(Shift, shift, kShifts) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32(), MachineType::Int32());
    m.Return((m.*dpi.constructor)(
        m.Parameter(0),
        (m.*shift.constructor)(m.Parameter(1), m.Parameter(2))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(shift.r_mode, s[0]->addressing_mode());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
  TRACED_FOREACH(Shift, shift, kShifts) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32(), MachineType::Int32());
    m.Return((m.*dpi.constructor)(
        (m.*shift.constructor)(m.Parameter(0), m.Parameter(1)),
        m.Parameter(2)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(dpi.reverse_arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(shift.r_mode, s[0]->addressing_mode());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}


TEST_P(InstructionSelectorDPITest, ShiftByImmediate) {
  const DPI dpi = GetParam();
  TRACED_FOREACH(Shift, shift, kShifts) {
    TRACED_FORRANGE(int32_t, imm, shift.i_low, shift.i_high) {
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                      MachineType::Int32());
      m.Return((m.*dpi.constructor)(
          m.Parameter(0),
          (m.*shift.constructor)(m.Parameter(1), m.Int32Constant(imm))));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(dpi.arch_opcode, s[0]->arch_opcode());
      EXPECT_EQ(shift.i_mode, s[0]->addressing_mode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(2)));
      EXPECT_EQ(1U, s[0]->OutputCount());
    }
  }
  TRACED_FOREACH(Shift, shift, kShifts) {
    TRACED_FORRANGE(int32_t, imm, shift.i_low, shift.i_high) {
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                      MachineType::Int32());
      m.Return((m.*dpi.constructor)(
          (m.*shift.constructor)(m.Parameter(0), m.Int32Constant(imm)),
          m.Parameter(1)));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(dpi.reverse_arch_opcode, s[0]->arch_opcode());
      EXPECT_EQ(shift.i_mode, s[0]->addressing_mode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(2)));
      EXPECT_EQ(1U, s[0]->OutputCount());
    }
  }
}


TEST_P(InstructionSelectorDPITest, BranchWithParameters) {
  const DPI dpi = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  RawMachineLabel a, b;
  m.Branch((m.*dpi.constructor)(m.Parameter(0), m.Parameter(1)), &a, &b);
  m.Bind(&a);
  m.Return(m.Int32Constant(1));
  m.Bind(&b);
  m.Return(m.Int32Constant(0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(dpi.test_arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kMode_Operand2_R, s[0]->addressing_mode());
  EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
  EXPECT_EQ(kNotEqual, s[0]->flags_condition());
}


TEST_P(InstructionSelectorDPITest, BranchWithImmediate) {
  const DPI dpi = GetParam();
  TRACED_FOREACH(int32_t, imm, kImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    RawMachineLabel a, b;
    m.Branch((m.*dpi.constructor)(m.Parameter(0), m.Int32Constant(imm)), &a,
             &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(dpi.test_arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_I, s[0]->addressing_mode());
    EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
    EXPECT_EQ(kNotEqual, s[0]->flags_condition());
  }
  TRACED_FOREACH(int32_t, imm, kImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    RawMachineLabel a, b;
    m.Branch((m.*dpi.constructor)(m.Int32Constant(imm), m.Parameter(0)), &a,
             &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(dpi.test_arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_I, s[0]->addressing_mode());
    EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
    EXPECT_EQ(kNotEqual, s[0]->flags_condition());
  }
}


TEST_P(InstructionSelectorDPITest, BranchWithShiftByParameter) {
  const DPI dpi = GetParam();
  TRACED_FOREACH(Shift, shift, kShifts) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32(), MachineType::Int32());
    RawMachineLabel a, b;
    m.Branch((m.*dpi.constructor)(
                 m.Parameter(0),
                 (m.*shift.constructor)(m.Parameter(1), m.Parameter(2))),
             &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(dpi.test_arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(shift.r_mode, s[0]->addressing_mode());
    EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
    EXPECT_EQ(kNotEqual, s[0]->flags_condition());
  }
  TRACED_FOREACH(Shift, shift, kShifts) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32(), MachineType::Int32());
    RawMachineLabel a, b;
    m.Branch((m.*dpi.constructor)(
                 (m.*shift.constructor)(m.Parameter(0), m.Parameter(1)),
                 m.Parameter(2)),
             &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(dpi.test_arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(shift.r_mode, s[0]->addressing_mode());
    EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
    EXPECT_EQ(kNotEqual, s[0]->flags_condition());
  }
}


TEST_P(InstructionSelectorDPITest, BranchWithShiftByImmediate) {
  const DPI dpi = GetParam();
  TRACED_FOREACH(Shift, shift, kShifts) {
    TRACED_FORRANGE(int32_t, imm, shift.i_low, shift.i_high) {
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                      MachineType::Int32());
      RawMachineLabel a, b;
      m.Branch((m.*dpi.constructor)(m.Parameter(0),
                                    (m.*shift.constructor)(
                                        m.Parameter(1), m.Int32Constant(imm))),
               &a, &b);
      m.Bind(&a);
      m.Return(m.Int32Constant(1));
      m.Bind(&b);
      m.Return(m.Int32Constant(0));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(dpi.test_arch_opcode, s[0]->arch_opcode());
      EXPECT_EQ(shift.i_mode, s[0]->addressing_mode());
      ASSERT_EQ(5U, s[0]->InputCount());
      EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(2)));
      EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
      EXPECT_EQ(kNotEqual, s[0]->flags_condition());
    }
  }
  TRACED_FOREACH(Shift, shift, kShifts) {
    TRACED_FORRANGE(int32_t, imm, shift.i_low, shift.i_high) {
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                      MachineType::Int32());
      RawMachineLabel a, b;
      m.Branch((m.*dpi.constructor)(
                   (m.*shift.constructor)(m.Parameter(0), m.Int32Constant(imm)),
                   m.Parameter(1)),
               &a, &b);
      m.Bind(&a);
      m.Return(m.Int32Constant(1));
      m.Bind(&b);
      m.Return(m.Int32Constant(0));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(dpi.test_arch_opcode, s[0]->arch_opcode());
      EXPECT_EQ(shift.i_mode, s[0]->addressing_mode());
      ASSERT_EQ(5U, s[0]->InputCount());
      EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(2)));
      EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
      EXPECT_EQ(kNotEqual, s[0]->flags_condition());
    }
  }
}


TEST_P(InstructionSelectorDPITest, BranchIfZeroWithParameters) {
  const DPI dpi = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  RawMachineLabel a, b;
  m.Branch(m.Word32Equal((m.*dpi.constructor)(m.Parameter(0), m.Parameter(1)),
                         m.Int32Constant(0)),
           &a, &b);
  m.Bind(&a);
  m.Return(m.Int32Constant(1));
  m.Bind(&b);
  m.Return(m.Int32Constant(0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(dpi.test_arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kMode_Operand2_R, s[0]->addressing_mode());
  EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
  EXPECT_EQ(kEqual, s[0]->flags_condition());
}


TEST_P(InstructionSelectorDPITest, BranchIfNotZeroWithParameters) {
  const DPI dpi = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  RawMachineLabel a, b;
  m.Branch(
      m.Word32NotEqual((m.*dpi.constructor)(m.Parameter(0), m.Parameter(1)),
                       m.Int32Constant(0)),
      &a, &b);
  m.Bind(&a);
  m.Return(m.Int32Constant(1));
  m.Bind(&b);
  m.Return(m.Int32Constant(0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(dpi.test_arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kMode_Operand2_R, s[0]->addressing_mode());
  EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
  EXPECT_EQ(kNotEqual, s[0]->flags_condition());
}


TEST_P(InstructionSelectorDPITest, BranchIfZeroWithImmediate) {
  const DPI dpi = GetParam();
  TRACED_FOREACH(int32_t, imm, kImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    RawMachineLabel a, b;
    m.Branch(m.Word32Equal(
                 (m.*dpi.constructor)(m.Parameter(0), m.Int32Constant(imm)),
                 m.Int32Constant(0)),
             &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(dpi.test_arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_I, s[0]->addressing_mode());
    EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
  }
  TRACED_FOREACH(int32_t, imm, kImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    RawMachineLabel a, b;
    m.Branch(m.Word32Equal(
                 (m.*dpi.constructor)(m.Int32Constant(imm), m.Parameter(0)),
                 m.Int32Constant(0)),
             &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(dpi.test_arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_I, s[0]->addressing_mode());
    EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
  }
}


TEST_P(InstructionSelectorDPITest, BranchIfNotZeroWithImmediate) {
  const DPI dpi = GetParam();
  TRACED_FOREACH(int32_t, imm, kImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    RawMachineLabel a, b;
    m.Branch(m.Word32NotEqual(
                 (m.*dpi.constructor)(m.Parameter(0), m.Int32Constant(imm)),
                 m.Int32Constant(0)),
             &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(dpi.test_arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_I, s[0]->addressing_mode());
    EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
    EXPECT_EQ(kNotEqual, s[0]->flags_condition());
  }
  TRACED_FOREACH(int32_t, imm, kImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    RawMachineLabel a, b;
    m.Branch(m.Word32NotEqual(
                 (m.*dpi.constructor)(m.Int32Constant(imm), m.Parameter(0)),
                 m.Int32Constant(0)),
             &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(1));
    m.Bind(&b);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(dpi.test_arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_I, s[0]->addressing_mode());
    EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
    EXPECT_EQ(kNotEqual, s[0]->flags_condition());
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest, InstructionSelectorDPITest,
                         ::testing::ValuesIn(kDPIs));

// -----------------------------------------------------------------------------
// Data processing instructions with overflow.

using InstructionSelectorODPITest = InstructionSelectorTestWithParam<ODPI>;

TEST_P(InstructionSelectorODPITest, OvfWithParameters) {
  const ODPI odpi = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  m.Return(
      m.Projection(1, (m.*odpi.constructor)(m.Parameter(0), m.Parameter(1))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(odpi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kMode_Operand2_R, s[0]->addressing_mode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_LE(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_set, s[0]->flags_mode());
  EXPECT_EQ(kOverflow, s[0]->flags_condition());
}


TEST_P(InstructionSelectorODPITest, OvfWithImmediate) {
  const ODPI odpi = GetParam();
  TRACED_FOREACH(int32_t, imm, kImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Projection(
        1, (m.*odpi.constructor)(m.Parameter(0), m.Int32Constant(imm))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(odpi.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_I, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_LE(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kOverflow, s[0]->flags_condition());
  }
  TRACED_FOREACH(int32_t, imm, kImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Projection(
        1, (m.*odpi.constructor)(m.Int32Constant(imm), m.Parameter(0))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(odpi.reverse_arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_I, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_LE(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kOverflow, s[0]->flags_condition());
  }
}


TEST_P(InstructionSelectorODPITest, OvfWithShiftByParameter) {
  const ODPI odpi = GetParam();
  TRACED_FOREACH(Shift, shift, kShifts) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32(), MachineType::Int32());
    m.Return(m.Projection(
        1, (m.*odpi.constructor)(
               m.Parameter(0),
               (m.*shift.constructor)(m.Parameter(1), m.Parameter(2)))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(odpi.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(shift.r_mode, s[0]->addressing_mode());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_LE(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kOverflow, s[0]->flags_condition());
  }
  TRACED_FOREACH(Shift, shift, kShifts) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32(), MachineType::Int32());
    m.Return(m.Projection(
        1, (m.*odpi.constructor)(
               (m.*shift.constructor)(m.Parameter(0), m.Parameter(1)),
               m.Parameter(0))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(odpi.reverse_arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(shift.r_mode, s[0]->addressing_mode());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_LE(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kOverflow, s[0]->flags_condition());
  }
}


TEST_P(InstructionSelectorODPITest, OvfWithShiftByImmediate) {
  const ODPI odpi = GetParam();
  TRACED_FOREACH(Shift, shift, kShifts) {
    TRACED_FORRANGE(int32_t, imm, shift.i_low, shift.i_high) {
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                      MachineType::Int32());
      m.Return(m.Projection(
          1, (m.*odpi.constructor)(m.Parameter(0),
                                   (m.*shift.constructor)(
                                       m.Parameter(1), m.Int32Constant(imm)))));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(odpi.arch_opcode, s[0]->arch_opcode());
      EXPECT_EQ(shift.i_mode, s[0]->addressing_mode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(2)));
      EXPECT_LE(1U, s[0]->OutputCount());
      EXPECT_EQ(kFlags_set, s[0]->flags_mode());
      EXPECT_EQ(kOverflow, s[0]->flags_condition());
    }
  }
  TRACED_FOREACH(Shift, shift, kShifts) {
    TRACED_FORRANGE(int32_t, imm, shift.i_low, shift.i_high) {
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                      MachineType::Int32());
      m.Return(m.Projection(
          1, (m.*odpi.constructor)(
                 (m.*shift.constructor)(m.Parameter(1), m.Int32Constant(imm)),
                 m.Parameter(0))));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(odpi.reverse_arch_opcode, s[0]->arch_opcode());
      EXPECT_EQ(shift.i_mode, s[0]->addressing_mode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(2)));
      EXPECT_LE(1U, s[0]->OutputCount());
      EXPECT_EQ(kFlags_set, s[0]->flags_mode());
      EXPECT_EQ(kOverflow, s[0]->flags_condition());
    }
  }
}


TEST_P(InstructionSelectorODPITest, ValWithParameters) {
  const ODPI odpi = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  m.Return(
      m.Projection(0, (m.*odpi.constructor)(m.Parameter(0), m.Parameter(1))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(odpi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kMode_Operand2_R, s[0]->addressing_mode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_LE(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_none, s[0]->flags_mode());
}


TEST_P(InstructionSelectorODPITest, ValWithImmediate) {
  const ODPI odpi = GetParam();
  TRACED_FOREACH(int32_t, imm, kImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Projection(
        0, (m.*odpi.constructor)(m.Parameter(0), m.Int32Constant(imm))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(odpi.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_I, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_LE(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_none, s[0]->flags_mode());
  }
  TRACED_FOREACH(int32_t, imm, kImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Projection(
        0, (m.*odpi.constructor)(m.Int32Constant(imm), m.Parameter(0))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(odpi.reverse_arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_I, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_LE(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_none, s[0]->flags_mode());
  }
}


TEST_P(InstructionSelectorODPITest, ValWithShiftByParameter) {
  const ODPI odpi = GetParam();
  TRACED_FOREACH(Shift, shift, kShifts) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32(), MachineType::Int32());
    m.Return(m.Projection(
        0, (m.*odpi.constructor)(
               m.Parameter(0),
               (m.*shift.constructor)(m.Parameter(1), m.Parameter(2)))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(odpi.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(shift.r_mode, s[0]->addressing_mode());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_LE(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_none, s[0]->flags_mode());
  }
  TRACED_FOREACH(Shift, shift, kShifts) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32(), MachineType::Int32());
    m.Return(m.Projection(
        0, (m.*odpi.constructor)(
               (m.*shift.constructor)(m.Parameter(0), m.Parameter(1)),
               m.Parameter(0))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(odpi.reverse_arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(shift.r_mode, s[0]->addressing_mode());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_LE(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_none, s[0]->flags_mode());
  }
}


TEST_P(InstructionSelectorODPITest, ValWithShiftByImmediate) {
  const ODPI odpi = GetParam();
  TRACED_FOREACH(Shift, shift, kShifts) {
    TRACED_FORRANGE(int32_t, imm, shift.i_low, shift.i_high) {
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                      MachineType::Int32());
      m.Return(m.Projection(
          0, (m.*odpi.constructor)(m.Parameter(0),
                                   (m.*shift.constructor)(
                                       m.Parameter(1), m.Int32Constant(imm)))));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(odpi.arch_opcode, s[0]->arch_opcode());
      EXPECT_EQ(shift.i_mode, s[0]->addressing_mode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(2)));
      EXPECT_LE(1U, s[0]->OutputCount());
      EXPECT_EQ(kFlags_none, s[0]->flags_mode());
    }
  }
  TRACED_FOREACH(Shift, shift, kShifts) {
    TRACED_FORRANGE(int32_t, imm, shift.i_low, shift.i_high) {
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                      MachineType::Int32());
      m.Return(m.Projection(
          0, (m.*odpi.constructor)(
                 (m.*shift.constructor)(m.Parameter(1), m.Int32Constant(imm)),
                 m.Parameter(0))));
      Stream s = m.Build();
      ASSERT_EQ(1U, s.size());
      EXPECT_EQ(odpi.reverse_arch_opcode, s[0]->arch_opcode());
      EXPECT_EQ(shift.i_mode, s[0]->addressing_mode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(2)));
      EXPECT_LE(1U, s[0]->OutputCount());
      EXPECT_EQ(kFlags_none, s[0]->flags_mode());
    }
  }
}


TEST_P(InstructionSelectorODPITest, BothWithParameters) {
  const ODPI odpi = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* n = (m.*odpi.constructor)(m.Parameter(0), m.Parameter(1));
  m.Return(m.Word32Equal(m.Projection(0, n), m.Projection(1, n)));
  Stream s = m.Build();
  ASSERT_LE(1U, s.size());
  EXPECT_EQ(odpi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kMode_Operand2_R, s[0]->addressing_mode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(2U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_set, s[0]->flags_mode());
  EXPECT_EQ(kOverflow, s[0]->flags_condition());
}


TEST_P(InstructionSelectorODPITest, BothWithImmediate) {
  const ODPI odpi = GetParam();
  TRACED_FOREACH(int32_t, imm, kImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Node* n = (m.*odpi.constructor)(m.Parameter(0), m.Int32Constant(imm));
    m.Return(m.Word32Equal(m.Projection(0, n), m.Projection(1, n)));
    Stream s = m.Build();
    ASSERT_LE(1U, s.size());
    EXPECT_EQ(odpi.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_I, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(2U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kOverflow, s[0]->flags_condition());
  }
  TRACED_FOREACH(int32_t, imm, kImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    Node* n = (m.*odpi.constructor)(m.Int32Constant(imm), m.Parameter(0));
    m.Return(m.Word32Equal(m.Projection(0, n), m.Projection(1, n)));
    Stream s = m.Build();
    ASSERT_LE(1U, s.size());
    EXPECT_EQ(odpi.reverse_arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_I, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(2U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kOverflow, s[0]->flags_condition());
  }
}


TEST_P(InstructionSelectorODPITest, BothWithShiftByParameter) {
  const ODPI odpi = GetParam();
  TRACED_FOREACH(Shift, shift, kShifts) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32(), MachineType::Int32());
    Node* n = (m.*odpi.constructor)(
        m.Parameter(0), (m.*shift.constructor)(m.Parameter(1), m.Parameter(2)));
    m.Return(m.Word32Equal(m.Projection(0, n), m.Projection(1, n)));
    Stream s = m.Build();
    ASSERT_LE(1U, s.size());
    EXPECT_EQ(odpi.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(shift.r_mode, s[0]->addressing_m
```