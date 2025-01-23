Response: The user wants a summary of the provided C++ code.
The code is a unit test file for the instruction selector in the V8 JavaScript engine, specifically for the ARM architecture.
It tests how various intermediate representation (IR) nodes are translated into ARM assembly instructions.
The tests cover different categories of instructions, including:
- Data processing instructions (arithmetic, bitwise)
- Floating-point arithmetic instructions
- Data processing instructions with overflow
- Shift instructions
- Memory access instructions (load, store)
- Conversions between floating-point types
- Comparisons (integer and floating-point)

The tests use a framework (`InstructionSelectorTestWithParam`) to generate test cases for different combinations of operands (registers, immediates, shifted registers).

To relate it to JavaScript, I need to find examples of JavaScript code that would result in the IR nodes being tested.
这个C++源代码文件是V8 JavaScript引擎的一部分，专门用于测试在ARM架构上的指令选择器（instruction selector）的功能。指令选择器的作用是将高级的、与平台无关的中间表示（IR - Intermediate Representation）代码转换成底层的、特定于ARM架构的机器指令。

具体来说，这个文件包含了一系列的单元测试，用于验证指令选择器对于不同类型的操作和操作数是否能够生成正确的ARM指令。 这些测试覆盖了：

1. **数据处理指令 (Data Processing Instructions)**:  例如加法、减法、按位与、按位或、按位异或等。测试验证了当操作数是寄存器、立即数或通过移位操作得到的数值时，指令选择器是否生成了正确的ARM指令 (`kArmAnd`, `kArmOrr`, `kArmEor`, `kArmAdd`, `kArmSub`, `kArmTst`, `kArmTeq`, `kArmCmn`, `kArmRsb`)。

2. **浮点运算指令 (Floating Point Arithmetic Instructions)**: 例如浮点数的加法、减法、乘法和除法。测试验证了指令选择器是否为 `Float32Add`, `Float64Add`, `Float32Sub`, `Float64Sub`, `Float32Mul`, `Float64Mul`, `Float32Div`, `Float64Div` 等操作生成了正确的ARM VFP (Vector Floating Point) 指令 (`kArmVaddF32`, `kArmVaddF64`, `kArmVsubF32`, `kArmVsubF64`, `kArmVmulF32`, `kArmVmulF64`, `kArmVdivF32`, `kArmVdivF64`)。

3. **带溢出检查的数据处理指令 (Data processing instructions with overflow)**:  例如带溢出检查的整数加法和减法 (`Int32AddWithOverflow`, `Int32SubWithOverflow`)，测试其对应的ARM指令 (`kArmAdd`, `kArmRsb`)以及如何处理溢出标志。

4. **移位指令 (Shifts)**: 例如算术右移 (`Word32Sar`)、逻辑左移 (`Word32Shl`)、逻辑右移 (`Word32Shr`) 和循环右移 (`Word32Ror`)。测试验证了当移位量是立即数或寄存器时，指令选择器生成正确的ARM移位指令 (`kMode_Operand2_R_ASR_I`, `kMode_Operand2_R_LSL_I`, `kMode_Operand2_R_LSR_I`, `kMode_Operand2_R_ROR_I` 和对应的寄存器移位模式)。

5. **内存访问指令 (Memory access instructions)**: 例如从内存加载数据 (`Load`) 和将数据存储到内存 (`Store`)。测试了不同数据类型（`Int8`, `Uint8`, `Int16`, `Uint16`, `Int32`, `Float32`, `Float64`）的加载和存储操作，以及当内存地址是通过寄存器偏移或立即数偏移计算得出时，指令选择器是否生成了正确的ARM加载/存储指令 (`kArmLdrsb`, `kArmLdrb`, `kArmLdrsh`, `kArmLdrh`, `kArmLdr`, `kArmVldrF32`, `kArmVldrF64`, `kArmStrb`, `kArmStrh`, `kArmStr`, `kArmVstrF32`, `kArmVstrF64`)。

6. **类型转换 (Conversions)**: 例如将32位浮点数转换为64位浮点数 (`ChangeFloat32ToFloat64`) 和将64位浮点数截断为32位浮点数 (`TruncateFloat64ToFloat32`)，测试了对应的ARM VFP 指令 (`kArmVcvtF64F32`, `kArmVcvtF32F64`)。

7. **比较指令 (Comparisons)**: 例如比较两个32位整数是否相等 (`Word32Equal`)、小于 (`Int32LessThan`, `Uint32LessThan`) 或小于等于 (`Int32LessThanOrEqual`, `Uint32LessThanOrEqual`)，以及浮点数的比较。测试验证了指令选择器是否生成了正确的ARM比较指令 (`kArmCmp`, `kArmVcmpF32`, `kArmVcmpF64`) 以及如何设置条件标志。

**与 JavaScript 的关系：**

JavaScript 代码在执行前会被 V8 引擎编译成中间表示（IR），然后指令选择器会将这些 IR 转换成特定架构的机器码。因此，这个文件中的测试直接关系到 V8 引擎如何将 JavaScript 的各种操作翻译成高效的 ARM 机器码。

**JavaScript 示例：**

1. **数据处理指令：**

   ```javascript
   let a = 10;
   let b = 5;
   let c = a + b; // 对应 Int32Add
   let d = a & b; // 对应 Word32And
   ```
   这段 JavaScript 代码中的加法操作 `a + b` 可能会被编译成 `Int32Add` IR 节点，指令选择器会将其转换为 ARM 的 `ADD` 指令 (`kArmAdd`)。按位与操作 `a & b` 对应 `Word32And`，会被转换为 ARM 的 `AND` 指令 (`kArmAnd`)。

2. **浮点运算指令：**

   ```javascript
   let x = 3.14;
   let y = 2.71;
   let z = x * y; // 对应 Float64Mul
   ```
   这段代码中的浮点数乘法 `x * y` 对应 `Float64Mul` IR 节点，指令选择器会将其转换为 ARM 的 VFP 乘法指令 (`kArmVmulF64`)。

3. **带溢出检查的数据处理指令：**

   ```javascript
   try {
     let maxInt = 2147483647;
     let overflow = maxInt + 1; // 可能会对应 Int32AddWithOverflow
     console.log(overflow);
   } catch (e) {
     console.error("Overflow detected!");
   }
   ```
   虽然 JavaScript 的数字类型是双精度浮点数，但在某些优化的场景下，V8 内部可能会使用 `Int32AddWithOverflow` 这样的节点来处理可能溢出的整数运算，指令选择器会将其转换为 ARM 的 `ADD` 指令，并设置溢出标志。

4. **移位指令：**

   ```javascript
   let num = 8; // 二进制 1000
   let shifted = num << 2; // 对应 Word32Shl (左移 2 位，结果为 32，二进制 100000)
   ```
   左移操作 `<<` 对应 `Word32Shl` IR 节点，指令选择器会将其转换为 ARM 的 `MOV` 指令，并使用 LSL 移位模式 (`kMode_Operand2_R_LSL_I`)。

5. **内存访问指令：**

   ```javascript
   let arr = [1, 2, 3];
   let first = arr[0]; // 对应 Load
   arr[1] = 4;       // 对应 Store
   ```
   访问数组元素 `arr[0]` 涉及到从内存中加载数据，这会对应 `Load` IR 节点，指令选择器会根据数据类型生成相应的 ARM 加载指令 (`kArmLdr` 等)。给数组元素赋值 `arr[1] = 4` 涉及到将数据存储到内存，对应 `Store` IR 节点，指令选择器会生成相应的 ARM 存储指令 (`kArmStr` 等)。

6. **类型转换：**

   ```javascript
   let float32 = new Float32Array([3.14])[0];
   let float64 = float32; // 对应 ChangeFloat32ToFloat64 (隐式转换)
   let truncated = Math.fround(5.7); // 对应 TruncateFloat64ToFloat32
   ```
   将 32 位浮点数赋值给 64 位浮点数变量时，会发生隐式的类型转换，对应 `ChangeFloat32ToFloat64` IR 节点，会被转换为 ARM 的 `VCVT.F64.F32` 指令 (`kArmVcvtF64F32`)。`Math.fround` 用于将数字转换为最接近的单精度浮点数，对应 `TruncateFloat64ToFloat32`，会被转换为 ARM 的 `VCVT.F32.F64` 指令 (`kArmVcvtF32F64`)。

7. **比较指令：**

   ```javascript
   let x = 5;
   let y = 10;
   if (x < y) { // 对应 Int32LessThan
     console.log("x is less than y");
   }

   let f1 = 2.5;
   let f2 = 3.7;
   if (f1 == f2) { // 对应 Float64Equal
     console.log("f1 is equal to f2");
   }
   ```
   整数比较 `x < y` 对应 `Int32LessThan` IR 节点，指令选择器会生成 ARM 的比较指令 (`kArmCmp`) 并设置相应的条件标志。浮点数比较 `f1 == f2` 对应 `Float64Equal`，会被转换为 ARM 的 VFP 比较指令 (`kArmVcmpF64`)。

总而言之，这个单元测试文件确保了 V8 引擎在将 JavaScript 代码编译为 ARM 机器码时，能够正确地选择和生成高效的指令。 这对于 JavaScript 代码在 ARM 设备（如移动设备）上的性能至关重要。
### 提示词
```
这是目录为v8/test/unittests/compiler/arm/instruction-selector-arm-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
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
    EXPECT_EQ(shift.r_mode, s[0]->addressing_mode());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(2U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kOverflow, s[0]->flags_condition());
  }
  TRACED_FOREACH(Shift, shift, kShifts) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32(), MachineType::Int32());
    Node* n = (m.*odpi.constructor)(
        (m.*shift.constructor)(m.Parameter(0), m.Parameter(1)), m.Parameter(2));
    m.Return(m.Word32Equal(m.Projection(0, n), m.Projection(1, n)));
    Stream s = m.Build();
    ASSERT_LE(1U, s.size());
    EXPECT_EQ(odpi.reverse_arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(shift.r_mode, s[0]->addressing_mode());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(2U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kOverflow, s[0]->flags_condition());
  }
}


TEST_P(InstructionSelectorODPITest, BothWithShiftByImmediate) {
  const ODPI odpi = GetParam();
  TRACED_FOREACH(Shift, shift, kShifts) {
    TRACED_FORRANGE(int32_t, imm, shift.i_low, shift.i_high) {
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                      MachineType::Int32());
      Node* n = (m.*odpi.constructor)(
          m.Parameter(0),
          (m.*shift.constructor)(m.Parameter(1), m.Int32Constant(imm)));
      m.Return(m.Word32Equal(m.Projection(0, n), m.Projection(1, n)));
      Stream s = m.Build();
      ASSERT_LE(1U, s.size());
      EXPECT_EQ(odpi.arch_opcode, s[0]->arch_opcode());
      EXPECT_EQ(shift.i_mode, s[0]->addressing_mode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(2)));
      EXPECT_EQ(2U, s[0]->OutputCount());
      EXPECT_EQ(kFlags_set, s[0]->flags_mode());
      EXPECT_EQ(kOverflow, s[0]->flags_condition());
    }
  }
  TRACED_FOREACH(Shift, shift, kShifts) {
    TRACED_FORRANGE(int32_t, imm, shift.i_low, shift.i_high) {
      StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                      MachineType::Int32());
      Node* n = (m.*odpi.constructor)(
          (m.*shift.constructor)(m.Parameter(0), m.Int32Constant(imm)),
          m.Parameter(1));
      m.Return(m.Word32Equal(m.Projection(0, n), m.Projection(1, n)));
      Stream s = m.Build();
      ASSERT_LE(1U, s.size());
      EXPECT_EQ(odpi.reverse_arch_opcode, s[0]->arch_opcode());
      EXPECT_EQ(shift.i_mode, s[0]->addressing_mode());
      ASSERT_EQ(3U, s[0]->InputCount());
      EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(2)));
      EXPECT_EQ(2U, s[0]->OutputCount());
      EXPECT_EQ(kFlags_set, s[0]->flags_mode());
      EXPECT_EQ(kOverflow, s[0]->flags_condition());
    }
  }
}


TEST_P(InstructionSelectorODPITest, BranchWithParameters) {
  const ODPI odpi = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  RawMachineLabel a, b;
  Node* n = (m.*odpi.constructor)(m.Parameter(0), m.Parameter(1));
  m.Branch(m.Projection(1, n), &a, &b);
  m.Bind(&a);
  m.Return(m.Int32Constant(0));
  m.Bind(&b);
  m.Return(m.Projection(0, n));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(odpi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kMode_Operand2_R, s[0]->addressing_mode());
  EXPECT_EQ(4U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
  EXPECT_EQ(kOverflow, s[0]->flags_condition());
}


TEST_P(InstructionSelectorODPITest, BranchWithImmediate) {
  const ODPI odpi = GetParam();
  TRACED_FOREACH(int32_t, imm, kImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    RawMachineLabel a, b;
    Node* n = (m.*odpi.constructor)(m.Parameter(0), m.Int32Constant(imm));
    m.Branch(m.Projection(1, n), &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(0));
    m.Bind(&b);
    m.Return(m.Projection(0, n));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(odpi.arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_I, s[0]->addressing_mode());
    ASSERT_EQ(4U, s[0]->InputCount());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
    EXPECT_EQ(kOverflow, s[0]->flags_condition());
  }
  TRACED_FOREACH(int32_t, imm, kImmediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    RawMachineLabel a, b;
    Node* n = (m.*odpi.constructor)(m.Int32Constant(imm), m.Parameter(0));
    m.Branch(m.Projection(1, n), &a, &b);
    m.Bind(&a);
    m.Return(m.Int32Constant(0));
    m.Bind(&b);
    m.Return(m.Projection(0, n));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(odpi.reverse_arch_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_I, s[0]->addressing_mode());
    ASSERT_EQ(4U, s[0]->InputCount());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
    EXPECT_EQ(kOverflow, s[0]->flags_condition());
  }
}


TEST_P(InstructionSelectorODPITest, BranchIfZeroWithParameters) {
  const ODPI odpi = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  RawMachineLabel a, b;
  Node* n = (m.*odpi.constructor)(m.Parameter(0), m.Parameter(1));
  m.Branch(m.Word32Equal(m.Projection(1, n), m.Int32Constant(0)), &a, &b);
  m.Bind(&a);
  m.Return(m.Projection(0, n));
  m.Bind(&b);
  m.Return(m.Int32Constant(0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(odpi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kMode_Operand2_R, s[0]->addressing_mode());
  EXPECT_EQ(4U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
  EXPECT_EQ(kNotOverflow, s[0]->flags_condition());
}


TEST_P(InstructionSelectorODPITest, BranchIfNotZeroWithParameters) {
  const ODPI odpi = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  RawMachineLabel a, b;
  Node* n = (m.*odpi.constructor)(m.Parameter(0), m.Parameter(1));
  m.Branch(m.Word32NotEqual(m.Projection(1, n), m.Int32Constant(0)), &a, &b);
  m.Bind(&a);
  m.Return(m.Projection(0, n));
  m.Bind(&b);
  m.Return(m.Int32Constant(0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(odpi.arch_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kMode_Operand2_R, s[0]->addressing_mode());
  EXPECT_EQ(4U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_branch, s[0]->flags_mode());
  EXPECT_EQ(kOverflow, s[0]->flags_condition());
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest, InstructionSelectorODPITest,
                         ::testing::ValuesIn(kODPIs));

// -----------------------------------------------------------------------------
// Shifts.

using InstructionSelectorShiftTest = InstructionSelectorTestWithParam<Shift>;

TEST_P(InstructionSelectorShiftTest, Parameters) {
  const Shift shift = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  m.Return((m.*shift.constructor)(m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmMov, s[0]->arch_opcode());
  EXPECT_EQ(shift.r_mode, s[0]->addressing_mode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}


TEST_P(InstructionSelectorShiftTest, Immediate) {
  const Shift shift = GetParam();
  TRACED_FORRANGE(int32_t, imm, shift.i_low, shift.i_high) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return((m.*shift.constructor)(m.Parameter(0), m.Int32Constant(imm)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmMov, s[0]->arch_opcode());
    EXPECT_EQ(shift.i_mode, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}


TEST_P(InstructionSelectorShiftTest, Word32EqualWithParameter) {
  const Shift shift = GetParam();
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32(), MachineType::Int32());
    m.Return(
        m.Word32Equal(m.Parameter(0),
                      (m.*shift.constructor)(m.Parameter(1), m.Parameter(2))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmCmp, s[0]->arch_opcode());
    EXPECT_EQ(shift.r_mode, s[0]->addressing_mode());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
  }
  {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32(), MachineType::Int32());
    m.Return(
        m.Word32Equal((m.*shift.constructor)(m.Parameter(1), m.Parameter(2)),
                      m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmCmp, s[0]->arch_opcode());
    EXPECT_EQ(shift.r_mode, s[0]->addressing_mode());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
  }
}


TEST_P(InstructionSelectorShiftTest, Word32EqualWithParameterAndImmediate) {
  const Shift shift = GetParam();
  TRACED_FORRANGE(int32_t, imm, shift.i_low, shift.i_high) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    m.Return(m.Word32Equal(
        (m.*shift.constructor)(m.Parameter(1), m.Int32Constant(imm)),
        m.Parameter(0)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmCmp, s[0]->arch_opcode());
    EXPECT_EQ(shift.i_mode, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(2)));
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
  }
  TRACED_FORRANGE(int32_t, imm, shift.i_low, shift.i_high) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    m.Return(m.Word32Equal(
        m.Parameter(0),
        (m.*shift.constructor)(m.Parameter(1), m.Int32Constant(imm))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmCmp, s[0]->arch_opcode());
    EXPECT_EQ(shift.i_mode, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(2)));
    EXPECT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
  }
}


TEST_P(InstructionSelectorShiftTest, Word32EqualToZeroWithParameters) {
  const Shift shift = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  m.Return(
      m.Word32Equal(m.Int32Constant(0),
                    (m.*shift.constructor)(m.Parameter(0), m.Parameter(1))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmMov, s[0]->arch_opcode());
  EXPECT_EQ(shift.r_mode, s[0]->addressing_mode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(2U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_set, s[0]->flags_mode());
  EXPECT_EQ(kEqual, s[0]->flags_condition());
}


TEST_P(InstructionSelectorShiftTest, Word32EqualToZeroWithImmediate) {
  const Shift shift = GetParam();
  TRACED_FORRANGE(int32_t, imm, shift.i_low, shift.i_high) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    m.Return(m.Word32Equal(
        m.Int32Constant(0),
        (m.*shift.constructor)(m.Parameter(0), m.Int32Constant(imm))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmMov, s[0]->arch_opcode());
    EXPECT_EQ(shift.i_mode, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(2U, s[0]->OutputCount());
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(kEqual, s[0]->flags_condition());
  }
}

TEST_P(InstructionSelectorShiftTest, Word32BitwiseNotWithParameters) {
  const Shift shift = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  m.Return(m.Word32BitwiseNot(
      (m.*shift.constructor)(m.Parameter(0), m.Parameter(1))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmMvn, s[0]->arch_opcode());
  EXPECT_EQ(shift.r_mode, s[0]->addressing_mode());
  EXPECT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

TEST_P(InstructionSelectorShiftTest, Word32BitwiseNotWithImmediate) {
  const Shift shift = GetParam();
  TRACED_FORRANGE(int32_t, imm, shift.i_low, shift.i_high) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32());
    m.Return(m.Word32BitwiseNot(
        (m.*shift.constructor)(m.Parameter(0), m.Int32Constant(imm))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmMvn, s[0]->arch_opcode());
    EXPECT_EQ(shift.i_mode, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(1)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_P(InstructionSelectorShiftTest,
       Word32AndWithWord32BitwiseNotWithParameters) {
  const Shift shift = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32(), MachineType::Int32());
  m.Return(
      m.Word32And(m.Parameter(0), m.Word32BitwiseNot((m.*shift.constructor)(
                                      m.Parameter(1), m.Parameter(2)))));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmBic, s[0]->arch_opcode());
  EXPECT_EQ(shift.r_mode, s[0]->addressing_mode());
  EXPECT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}

TEST_P(InstructionSelectorShiftTest,
       Word32AndWithWord32BitwiseNotWithImmediate) {
  const Shift shift = GetParam();
  TRACED_FORRANGE(int32_t, imm, shift.i_low, shift.i_high) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    m.Return(m.Word32And(m.Parameter(0),
                         m.Word32BitwiseNot((m.*shift.constructor)(
                             m.Parameter(1), m.Int32Constant(imm)))));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmBic, s[0]->arch_opcode());
    EXPECT_EQ(shift.i_mode, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(imm, s.ToInt32(s[0]->InputAt(2)));
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest, InstructionSelectorShiftTest,
                         ::testing::ValuesIn(kShifts));

// -----------------------------------------------------------------------------
// Memory access instructions.


namespace {

struct MemoryAccess {
  MachineType type;
  ArchOpcode ldr_opcode;
  ArchOpcode str_opcode;
  bool (InstructionSelectorTest::Stream::*val_predicate)(
      const InstructionOperand*) const;
  const int32_t immediates[40];
};


std::ostream& operator<<(std::ostream& os, const MemoryAccess& memacc) {
  return os << memacc.type;
}


const MemoryAccess kMemoryAccesses[] = {
    {MachineType::Int8(),
     kArmLdrsb,
     kArmStrb,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3340, -3231, -3224, -3088, -1758, -1203, -123, -117, -91, -89,
      -87, -86, -82, -44, -23, -3, 0, 7, 10, 39, 52, 69, 71, 91, 92, 107, 109,
      115, 124, 286, 655, 1362, 1569, 2587, 3067, 3096, 3462, 3510, 4095}},
    {MachineType::Uint8(),
     kArmLdrb,
     kArmStrb,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -3914, -3536, -3234, -3185, -3169, -1073, -990, -859, -720, -434,
      -127, -124, -122, -105, -91, -86, -64, -55, -53, -30, -10, -3, 0, 20, 28,
      39, 58, 64, 73, 75, 100, 108, 121, 686, 963, 1363, 2759, 3449, 4095}},
    {MachineType::Int16(),
     kArmLdrsh,
     kArmStrh,
     &InstructionSelectorTest::Stream::IsInteger,
     {-255, -251, -232, -220, -144, -138, -130, -126, -116, -115, -102, -101,
      -98, -69, -59, -56, -39, -35, -23, -19, -7, 0, 22, 26, 37, 68, 83, 87, 98,
      102, 108, 111, 117, 171, 195, 203, 204, 245, 246, 255}},
    {MachineType::Uint16(),
     kArmLdrh,
     kArmStrh,
     &InstructionSelectorTest::Stream::IsInteger,
     {-255, -230, -201, -172, -125, -119, -118, -105, -98, -79, -54, -42, -41,
      -32, -12, -11, -5, -4, 0, 5, 9, 25, 28, 51, 58, 60, 89, 104, 108, 109,
      114, 116, 120, 138, 150, 161, 166, 172, 228, 255}},
    {MachineType::Int32(),
     kArmLdr,
     kArmStr,
     &InstructionSelectorTest::Stream::IsInteger,
     {-4095, -1898, -1685, -1562, -1408, -1313, -344, -128, -116, -100, -92,
      -80, -72, -71, -56, -25, -21, -11, -9, 0, 3, 5, 27, 28, 42, 52, 63, 88,
      93, 97, 125, 846, 1037, 2102, 2403, 2597, 2632, 2997, 3935, 4095}},
    {MachineType::Float32(),
     kArmVldrF32,
     kArmVstrF32,
     &InstructionSelectorTest::Stream::IsDouble,
     {-1020, -928, -896, -772, -728, -680, -660, -488, -372, -112, -100, -92,
      -84, -80, -72, -64, -60, -56, -52, -48, -36, -32, -20, -8, -4, 0, 8, 20,
      24, 40, 64, 112, 204, 388, 516, 852, 856, 976, 988, 1020}},
    {MachineType::Float64(),
     kArmVldrF64,
     kArmVstrF64,
     &InstructionSelectorTest::Stream::IsDouble,
     {-1020, -948, -796, -696, -612, -364, -320, -308, -128, -112, -108, -104,
      -96, -84, -80, -56, -48, -40, -20, 0, 24, 28, 36, 48, 64, 84, 96, 100,
      108, 116, 120, 140, 156, 408, 432, 444, 772, 832, 940, 1020}}};

}  // namespace

using InstructionSelectorMemoryAccessTest =
    InstructionSelectorTestWithParam<MemoryAccess>;

TEST_P(InstructionSelectorMemoryAccessTest, LoadWithParameters) {
  const MemoryAccess memacc = GetParam();
  StreamBuilder m(this, memacc.type, MachineType::Pointer(),
                  MachineType::Int32());
  m.Return(m.Load(memacc.type, m.Parameter(0), m.Parameter(1)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(memacc.ldr_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kMode_Offset_RR, s[0]->addressing_mode());
  EXPECT_EQ(2U, s[0]->InputCount());
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_TRUE((s.*memacc.val_predicate)(s[0]->Output()));
}


TEST_P(InstructionSelectorMemoryAccessTest, LoadWithImmediateIndex) {
  const MemoryAccess memacc = GetParam();
  TRACED_FOREACH(int32_t, index, memacc.immediates) {
    StreamBuilder m(this, memacc.type, MachineType::Pointer());
    m.Return(m.Load(memacc.type, m.Parameter(0), m.Int32Constant(index)));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(memacc.ldr_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Offset_RI, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(1)->kind());
    EXPECT_EQ(index, s.ToInt32(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_TRUE((s.*memacc.val_predicate)(s[0]->Output()));
  }
}


TEST_P(InstructionSelectorMemoryAccessTest, StoreWithParameters) {
  const MemoryAccess memacc = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Pointer(),
                  MachineType::Int32(), memacc.type);
  m.Store(memacc.type.representation(), m.Parameter(0), m.Parameter(1),
          m.Parameter(2), kNoWriteBarrier);
  m.Return(m.Int32Constant(0));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(memacc.str_opcode, s[0]->arch_opcode());
  EXPECT_EQ(kMode_Offset_RR, s[0]->addressing_mode());
  EXPECT_EQ(3U, s[0]->InputCount());
  EXPECT_EQ(0U, s[0]->OutputCount());
}


TEST_P(InstructionSelectorMemoryAccessTest, StoreWithImmediateIndex) {
  const MemoryAccess memacc = GetParam();
  TRACED_FOREACH(int32_t, index, memacc.immediates) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Pointer(),
                    memacc.type);
    m.Store(memacc.type.representation(), m.Parameter(0),
            m.Int32Constant(index), m.Parameter(1), kNoWriteBarrier);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(memacc.str_opcode, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Offset_RI, s[0]->addressing_mode());
    ASSERT_EQ(3U, s[0]->InputCount());
    ASSERT_EQ(InstructionOperand::IMMEDIATE, s[0]->InputAt(2)->kind());
    EXPECT_EQ(index, s.ToInt32(s[0]->InputAt(2)));
    EXPECT_EQ(0U, s[0]->OutputCount());
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorMemoryAccessTest,
                         ::testing::ValuesIn(kMemoryAccesses));

TEST_F(InstructionSelectorMemoryAccessTest, LoadWithShiftedIndex) {
  TRACED_FORRANGE(int, immediate_shift, 1, 31) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Pointer(),
                    MachineType::Int32());
    Node* const index =
        m.Word32Shl(m.Parameter(1), m.Int32Constant(immediate_shift));
    m.Return(m.Load(MachineType::Int32(), m.Parameter(0), index));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmLdr, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_LSL_I, s[0]->addressing_mode());
    EXPECT_EQ(3U, s[0]->InputCount());
    EXPECT_EQ(1U, s[0]->OutputCount());
  }
}

TEST_F(InstructionSelectorMemoryAccessTest, StoreWithShiftedIndex) {
  TRACED_FORRANGE(int, immediate_shift, 1, 31) {
    StreamBuilder m(this, MachineType::Int32(), MachineType::Pointer(),
                    MachineType::Int32(), MachineType::Int32());
    Node* const index =
        m.Word32Shl(m.Parameter(1), m.Int32Constant(immediate_shift));
    m.Store(MachineRepresentation::kWord32, m.Parameter(0), index,
            m.Parameter(2), kNoWriteBarrier);
    m.Return(m.Int32Constant(0));
    Stream s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmStr, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R_LSL_I, s[0]->addressing_mode());
    EXPECT_EQ(4U, s[0]->InputCount());
    EXPECT_EQ(0U, s[0]->OutputCount());
  }
}

// -----------------------------------------------------------------------------
// Conversions.


TEST_F(InstructionSelectorTest, ChangeFloat32ToFloat64WithParameter) {
  StreamBuilder m(this, MachineType::Float64(), MachineType::Float32());
  m.Return(m.ChangeFloat32ToFloat64(m.Parameter(0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmVcvtF64F32, s[0]->arch_opcode());
  EXPECT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}


TEST_F(InstructionSelectorTest, TruncateFloat64ToFloat32WithParameter) {
  StreamBuilder m(this, MachineType::Float32(), MachineType::Float64());
  m.Return(m.TruncateFloat64ToFloat32(m.Parameter(0)));
  Stream s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmVcvtF32F64, s[0]->arch_opcode());
  EXPECT_EQ(1U, s[0]->InputCount());
  EXPECT_EQ(1U, s[0]->OutputCount());
}


// -----------------------------------------------------------------------------
// Comparisons.


namespace {

struct Comparison {
  Constructor constructor;
  const char* constructor_name;
  FlagsCondition flags_condition;
  FlagsCondition negated_flags_condition;
  FlagsCondition commuted_flags_condition;
};


std::ostream& operator<<(std::ostream& os, const Comparison& cmp) {
  return os << cmp.constructor_name;
}


const Comparison kComparisons[] = {
    {&RawMachineAssembler::Word32Equal, "Word32Equal", kEqual, kNotEqual,
     kEqual},
    {&RawMachineAssembler::Int32LessThan, "Int32LessThan", kSignedLessThan,
     kSignedGreaterThanOrEqual, kSignedGreaterThan},
    {&RawMachineAssembler::Int32LessThanOrEqual, "Int32LessThanOrEqual",
     kSignedLessThanOrEqual, kSignedGreaterThan, kSignedGreaterThanOrEqual},
    {&RawMachineAssembler::Uint32LessThan, "Uint32LessThan", kUnsignedLessThan,
     kUnsignedGreaterThanOrEqual, kUnsignedGreaterThan},
    {&RawMachineAssembler::Uint32LessThanOrEqual, "Uint32LessThanOrEqual",
     kUnsignedLessThanOrEqual, kUnsignedGreaterThan,
     kUnsignedGreaterThanOrEqual}};

}  // namespace

using InstructionSelectorComparisonTest =
    InstructionSelectorTestWithParam<Comparison>;

TEST_P(InstructionSelectorComparisonTest, Parameters) {
  const Comparison& cmp = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                  MachineType::Int32());
  Node* const p0 = m.Parameter(0);
  Node* const p1 = m.Parameter(1);
  Node* const r = (m.*cmp.constructor)(p0, p1);
  m.Return(r);
  Stream const s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmCmp, s[0]->arch_opcode());
  EXPECT_EQ(kMode_Operand2_R, s[0]->addressing_mode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
  EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->OutputAt(0)));
  EXPECT_EQ(kFlags_set, s[0]->flags_mode());
  EXPECT_EQ(cmp.flags_condition, s[0]->flags_condition());
}


TEST_P(InstructionSelectorComparisonTest, Word32EqualWithZero) {
  {
    const Comparison& cmp = GetParam();
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
    Node* const r =
        m.Word32Equal((m.*cmp.constructor)(p0, p1), m.Int32Constant(0));
    m.Return(r);
    Stream const s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmCmp, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->OutputAt(0)));
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(cmp.negated_flags_condition, s[0]->flags_condition());
  }
  {
    const Comparison& cmp = GetParam();
    StreamBuilder m(this, MachineType::Int32(), MachineType::Int32(),
                    MachineType::Int32());
    Node* const p0 = m.Parameter(0);
    Node* const p1 = m.Parameter(1);
    Node* const r =
        m.Word32Equal(m.Int32Constant(0), (m.*cmp.constructor)(p0, p1));
    m.Return(r);
    Stream const s = m.Build();
    ASSERT_EQ(1U, s.size());
    EXPECT_EQ(kArmCmp, s[0]->arch_opcode());
    EXPECT_EQ(kMode_Operand2_R, s[0]->addressing_mode());
    ASSERT_EQ(2U, s[0]->InputCount());
    EXPECT_EQ(s.ToVreg(p0), s.ToVreg(s[0]->InputAt(0)));
    EXPECT_EQ(s.ToVreg(p1), s.ToVreg(s[0]->InputAt(1)));
    ASSERT_EQ(1U, s[0]->OutputCount());
    EXPECT_EQ(s.ToVreg(r), s.ToVreg(s[0]->OutputAt(0)));
    EXPECT_EQ(kFlags_set, s[0]->flags_mode());
    EXPECT_EQ(cmp.negated_flags_condition, s[0]->flags_condition());
  }
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorComparisonTest,
                         ::testing::ValuesIn(kComparisons));

// -----------------------------------------------------------------------------
// Floating point comparisons.


namespace {

const Comparison kF32Comparisons[] = {
    {&RawMachineAssembler::Float32Equal, "Float32Equal", kEqual, kNotEqual,
     kEqual},
    {&RawMachineAssembler::Float32LessThan, "Float32LessThan",
     kFloatLessThan, kFloatGreaterThanOrEqualOrUnordered, kFloatGreaterThan},
    {&RawMachineAssembler::Float32LessThanOrEqual, "Float32LessThanOrEqual",
     kFloatLessThanOrEqual, kFloatGreaterThanOrUnordered,
     kFloatGreaterThanOrEqual}};

}  // namespace

using InstructionSelectorF32ComparisonTest =
    InstructionSelectorTestWithParam<Comparison>;

TEST_P(InstructionSelectorF32ComparisonTest, WithParameters) {
  const Comparison& cmp = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Float32(),
                  MachineType::Float32());
  m.Return((m.*cmp.constructor)(m.Parameter(0), m.Parameter(1)));
  Stream const s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmVcmpF32, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_set, s[0]->flags_mode());
  EXPECT_EQ(cmp.flags_condition, s[0]->flags_condition());
}


TEST_P(InstructionSelectorF32ComparisonTest, NegatedWithParameters) {
  const Comparison& cmp = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Float32(),
                  MachineType::Float32());
  m.Return(
      m.Word32BinaryNot((m.*cmp.constructor)(m.Parameter(0), m.Parameter(1))));
  Stream const s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmVcmpF32, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_set, s[0]->flags_mode());
  EXPECT_EQ(cmp.negated_flags_condition, s[0]->flags_condition());
}


TEST_P(InstructionSelectorF32ComparisonTest, WithImmediateZeroOnRight) {
  const Comparison& cmp = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Float32());
  m.Return((m.*cmp.constructor)(m.Parameter(0), m.Float32Constant(0.0)));
  Stream const s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmVcmpF32, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_TRUE(s[0]->InputAt(1)->IsImmediate());
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_set, s[0]->flags_mode());
  EXPECT_EQ(cmp.flags_condition, s[0]->flags_condition());
}


TEST_P(InstructionSelectorF32ComparisonTest, WithImmediateZeroOnLeft) {
  const Comparison& cmp = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Float32());
  m.Return((m.*cmp.constructor)(m.Float32Constant(0.0f), m.Parameter(0)));
  Stream const s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmVcmpF32, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_TRUE(s[0]->InputAt(1)->IsImmediate());
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_set, s[0]->flags_mode());
  EXPECT_EQ(cmp.commuted_flags_condition, s[0]->flags_condition());
}

INSTANTIATE_TEST_SUITE_P(InstructionSelectorTest,
                         InstructionSelectorF32ComparisonTest,
                         ::testing::ValuesIn(kF32Comparisons));

namespace {

const Comparison kF64Comparisons[] = {
    {&RawMachineAssembler::Float64Equal, "Float64Equal", kEqual, kNotEqual,
     kEqual},
    {&RawMachineAssembler::Float64LessThan, "Float64LessThan",
     kFloatLessThan, kFloatGreaterThanOrEqualOrUnordered, kFloatGreaterThan},
    {&RawMachineAssembler::Float64LessThanOrEqual, "Float64LessThanOrEqual",
     kFloatLessThanOrEqual, kFloatGreaterThanOrUnordered,
     kFloatGreaterThanOrEqual}};

}  // namespace

using InstructionSelectorF64ComparisonTest =
    InstructionSelectorTestWithParam<Comparison>;

TEST_P(InstructionSelectorF64ComparisonTest, WithParameters) {
  const Comparison& cmp = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Float64(),
                  MachineType::Float64());
  m.Return((m.*cmp.constructor)(m.Parameter(0), m.Parameter(1)));
  Stream const s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmVcmpF64, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_set, s[0]->flags_mode());
  EXPECT_EQ(cmp.flags_condition, s[0]->flags_condition());
}


TEST_P(InstructionSelectorF64ComparisonTest, NegatedWithParameters) {
  const Comparison& cmp = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Float64(),
                  MachineType::Float64());
  m.Return(
      m.Word32BinaryNot((m.*cmp.constructor)(m.Parameter(0), m.Parameter(1))));
  Stream const s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmVcmpF64, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_set, s[0]->flags_mode());
  EXPECT_EQ(cmp.negated_flags_condition, s[0]->flags_condition());
}


TEST_P(InstructionSelectorF64ComparisonTest, WithImmediateZeroOnRight) {
  const Comparison& cmp = GetParam();
  StreamBuilder m(this, MachineType::Int32(), MachineType::Float64());
  m.Return((m.*cmp.constructor)(m.Parameter(0), m.Float64Constant(0.0)));
  Stream const s = m.Build();
  ASSERT_EQ(1U, s.size());
  EXPECT_EQ(kArmVcmpF64, s[0]->arch_opcode());
  ASSERT_EQ(2U, s[0]->InputCount());
  EXPECT_TRUE(s[0]->InputAt(1)->IsImmediate());
  ASSERT_EQ(1U, s[0]->OutputCount());
  EXPECT_EQ(kFlags_set, s[0]->flags_mode());
  EXPECT_EQ(cmp.flags_condition, s[0]->flags_condition()
```