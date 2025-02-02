Response:
The user wants to understand the functionality of the C++ code snippet provided, which is a part of the V8 JavaScript engine. The file is `v8/src/diagnostics/x64/disasm-x64.cc`.

Here's a breakdown of the request and a plan to address it:

1. **List the functionalities:** This requires analyzing the code and identifying the key actions and purposes of different code sections. Focus on what the code *does*.
2. **Check for Torque source:**  The filename ends with `.cc`, not `.tq`. So, it's not a Torque source file.
3. **Relationship with JavaScript and example:** This involves understanding if the code directly relates to executing JavaScript code or is more of a development/debugging tool. Since the path includes "diagnostics" and the content seems to involve instruction decoding, it's likely a tool. Provide a simple JavaScript example to show where this type of low-level analysis might be relevant.
4. **Code logic and example:** Look for specific algorithms or processes within the code. The core logic is instruction decoding. I can provide a hypothetical byte sequence and trace how the disassembler might process it.
5. **Common programming errors:**  Consider typical mistakes developers might make when working with assembly or low-level debugging, which this disassembler might help identify.
6. **Summarize the function:** Provide a concise overview of the code's purpose.

**Mental Sandbox Simulation:**

* **Functionalities:**  The code defines structures and tables related to x64 assembly instructions (mnemonics, operand types). It has a `DisassemblerX64` class that seems to take raw byte instructions and convert them into a human-readable format. It handles prefixes, opcodes, ModR/M bytes, SIB bytes, and immediate values.
* **Torque:**  Easy check - filename extension.
* **JavaScript Relation:** Disassemblers are useful for debugging and understanding the low-level code generated by the JavaScript engine's compiler. A simple JavaScript function can be compiled into machine code, which this disassembler could analyze.
* **Code Logic:**  The `InstructionDecode` method and the various `Print...Operand` methods are key. I can imagine feeding a simple "mov" instruction and showing how the ModR/M byte is parsed to identify the registers involved.
* **Programming Errors:**  Thinking about assembly errors – incorrect register usage, wrong operand sizes, invalid instruction sequences – these can be visualized using the output of a disassembler.
* **Summary:** The file implements a disassembler for x64 architecture, used for examining the machine code generated by V8.

**Constraint Checklist:**

* 列举一下它的功能: Yes
* 如果v8/src/diagnostics/x64/disasm-x64.cc以.tq结尾，那它是个v8 torque源代码: Yes
* 如果它与javascript的功能有关系，请用javascript举例说明: Yes
* 如果有代码逻辑推理，请给出假设输入与输出: Yes
* 如果涉及用户常见的编程错误，请举例说明: Yes
* 这是第1部分，共4部分，请归纳一下它的功能: Yes

**Confidence Score:** 5/5 - I'm confident I can address all aspects of the request.

Strategizing complete. Proceeding with response generation.

这是 `v8/src/diagnostics/x64/disasm-x64.cc` 文件的第一部分，它是一个 V8 源代码文件，主要功能是为 **x64 架构** 的机器码提供反汇编功能。

**具体功能归纳:**

1. **定义 x64 指令的结构和属性:**
   - 定义了 `OperandType` 枚举，用于描述指令操作数的类型和顺序。
   - 定义了 `ByteMnemonic` 结构体，将字节码与助记符和操作数顺序关联起来。
   - 定义了多个 `ByteMnemonic` 类型的静态常量数组（例如 `two_operands_instr`, `zero_operands_instr` 等），这些数组构成了基本指令集的查找表。
   - 定义了 `InstructionType` 枚举，用于标识不同类型的指令（例如，零操作数指令、双操作数指令等）。
   - 定义了 `Prefixes` 枚举，列举了 x64 指令的前缀字节。
   - 定义了 `InstructionDesc` 结构体，用于存储指令的助记符、类型、操作数顺序和是否为字节操作等信息。
   - 定义了 `InstructionTable` 类，用于管理和查找指令描述符。它通过 `ByteMnemonic` 数组来初始化指令表。

2. **实现 x64 指令的反汇编逻辑:**
   - 定义了 `DisassemblerX64` 类，这是反汇编器的核心。
   - `InstructionDecode` 方法（在后续部分）是反汇编单个指令的主要入口点。
   - 类中包含用于解析指令前缀（如 REX 前缀、操作数大小前缀等）的成员变量和方法。
   - 类中包含用于解析 ModR/M 和 SIB 字节的方法 (`get_modrm`, `get_sib`)，这些字节用于确定操作数（寄存器、内存地址）。
   - 类中包含用于格式化输出的方法 (`AppendToBuffer`)。
   - 类中包含用于打印不同类型操作数的方法 (`PrintRightOperand`, `PrintRightByteOperand`, `PrintImmediate` 等）。
   - 类中包含用于处理不同指令格式的方法 (`PrintOperands`, `PrintImmediateOp`, `TwoByteOpcodeInstruction` 等）。

**关于文件类型:**

`v8/src/diagnostics/x64/disasm-x64.cc` 的文件后缀是 `.cc`，这表明它是一个 **C++ 源代码文件**。如果它的后缀是 `.tq`，那么它才是一个 V8 Torque 源代码文件。

**与 JavaScript 功能的关系:**

`v8/src/diagnostics/x64/disasm-x64.cc` 的功能与 JavaScript 的执行密切相关，但它本身不是直接执行 JavaScript 代码的部分。相反，它是一个 **诊断和调试工具**。

V8 引擎会将 JavaScript 代码编译成机器码以便执行。当开发者需要理解 V8 生成的机器码，或者在进行底层调试时，反汇编器就派上了用场。它可以将机器码字节转换成人类可读的汇编指令。

**JavaScript 示例:**

假设有以下简单的 JavaScript 函数：

```javascript
function add(a, b) {
  return a + b;
}

add(1, 2);
```

当 V8 引擎执行这段代码时，它会将 `add` 函数编译成 x64 机器码（在 x64 架构上）。  `disasm-x64.cc` 中实现的 disassembler 可以用来查看生成的机器码，例如：

```assembly
;; 假设 V8 生成的机器码片段如下 (这只是一个示例)：
0:  55                   push   rbp
1:  48 89 e5             mov    rbp,rsp
4:  8b 45 08             mov    eax,DWORD PTR [rbp+0x8]
7:  03 45 10             add    eax,DWORD PTR [rbp+0x10]
a:  5d                   pop    rbp
b:  c3                   ret
```

`disasm-x64.cc` 的代码负责将 `55`, `48 89 e5`, `8b 45 08` 等字节序列转换为 `push rbp`, `mov rbp,rsp`, `mov eax,DWORD PTR [rbp+0x8]` 这样的汇编指令。

**代码逻辑推理 (假设输入与输出):**

**假设输入:**  字节序列 `01 00`

**推理过程:**

1. `InstructionDecode` 方法（在后续部分）读取第一个字节 `01`。
2. 查找 `two_operands_instr` 表，找到 `0x01` 对应的条目，其 `mnem` 为 "add"，`op_order_` 为 `OPER_REG_OP_ORDER`。
3. 根据 `OPER_REG_OP_ORDER`，这是一个操作数到寄存器的操作。
4. 读取下一个字节 `00`，这是一个 ModR/M 字节。
5. 解析 ModR/M 字节 `00`:
   - `mod = 0`
   - `regop = 0`
   - `rm = 0`
6. 根据 `mod = 0` 和 `rm = 0`，右操作数是一个内存地址 `[rax]`。
7. 根据 `regop = 0`，左操作数是 `rax` 寄存器。
8. 根据指令的上下文和默认操作数大小，假设是 32 位操作。

**假设输出 (反汇编结果):** `add    dword ptr [rax],eax`

**涉及用户常见的编程错误 (反汇编角度):**

虽然用户通常不直接编写机器码，但在理解程序行为时，反汇编可以帮助识别一些潜在的编程错误，例如：

1. **错误的函数调用约定:**  如果反汇编结果显示函数调用前后堆栈不平衡，可能是调用约定不匹配导致的。

   **例子 (假设反汇编输出显示):**
   ```assembly
   call   some_function
   add    esp, 4  ; 应该清理更多堆栈空间
   ```
   这可能表明 `some_function` 是一个 `stdcall` 函数，而调用者没有正确清理堆栈。

2. **缓冲区溢出:**  反汇编代码可能会揭示对栈或堆上缓冲区的越界访问。

   **例子 (假设反汇编输出显示):**
   ```assembly
   mov    dword ptr [rbp-0x100], eax  ; 向一个可能过小的缓冲区写入
   ```
   如果 `rbp-0x100` 指向的缓冲区小于 `eax` 的大小，则可能发生溢出。

3. **类型混淆:**  在动态语言中，类型错误有时会在运行时才暴露。反汇编生成的代码可能显示对不同类型数据的不一致操作。

   **例子 (虽然更复杂，但概念上):**  如果 JavaScript 中将一个数字误当作指针使用，反汇编可能会显示将该数字值用作内存地址进行访问。

**总结 `v8/src/diagnostics/x64/disasm-x64.cc` 第一部分的功能:**

这部分代码主要负责定义了 x64 指令集的各种结构和查找表，为后续实现指令的解码和格式化输出奠定了基础。它描述了指令的构成要素，例如操作数的类型、指令的助记符以及不同指令类型的分类。这部分是 x64 反汇编器的静态数据部分。

### 提示词
```
这是目录为v8/src/diagnostics/x64/disasm-x64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/diagnostics/x64/disasm-x64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2011 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cassert>
#include <cinttypes>
#include <cstdarg>
#include <cstdio>

#if V8_TARGET_ARCH_X64

#include "src/base/compiler-specific.h"
#include "src/base/lazy-instance.h"
#include "src/base/memory.h"
#include "src/base/strings.h"
#include "src/codegen/x64/fma-instr.h"
#include "src/codegen/x64/register-x64.h"
#include "src/codegen/x64/sse-instr.h"
#include "src/common/globals.h"
#include "src/diagnostics/disasm.h"

namespace disasm {

enum OperandType {
  UNSET_OP_ORDER = 0,
  // Operand size decides between 16, 32 and 64 bit operands.
  REG_OPER_OP_ORDER = 1,  // Register destination, operand source.
  OPER_REG_OP_ORDER = 2,  // Operand destination, register source.
  // Fixed 8-bit operands.
  BYTE_SIZE_OPERAND_FLAG = 4,
  BYTE_REG_OPER_OP_ORDER = REG_OPER_OP_ORDER | BYTE_SIZE_OPERAND_FLAG,
  BYTE_OPER_REG_OP_ORDER = OPER_REG_OP_ORDER | BYTE_SIZE_OPERAND_FLAG,
  // XMM registers/operands can be mixed with normal operands.
  OPER_XMMREG_OP_ORDER,
  XMMREG_OPER_OP_ORDER,
  XMMREG_XMMOPER_OP_ORDER,
  XMMOPER_XMMREG_OP_ORDER,
};

//------------------------------------------------------------------
// Tables
//------------------------------------------------------------------
struct ByteMnemonic {
  int b;  // -1 terminates, otherwise must be in range (0..255)
  OperandType op_order_;
  const char* mnem;
};

static const ByteMnemonic two_operands_instr[] = {
    {0x00, BYTE_OPER_REG_OP_ORDER, "add"},
    {0x01, OPER_REG_OP_ORDER, "add"},
    {0x02, BYTE_REG_OPER_OP_ORDER, "add"},
    {0x03, REG_OPER_OP_ORDER, "add"},
    {0x08, BYTE_OPER_REG_OP_ORDER, "or"},
    {0x09, OPER_REG_OP_ORDER, "or"},
    {0x0A, BYTE_REG_OPER_OP_ORDER, "or"},
    {0x0B, REG_OPER_OP_ORDER, "or"},
    {0x10, BYTE_OPER_REG_OP_ORDER, "adc"},
    {0x11, OPER_REG_OP_ORDER, "adc"},
    {0x12, BYTE_REG_OPER_OP_ORDER, "adc"},
    {0x13, REG_OPER_OP_ORDER, "adc"},
    {0x18, BYTE_OPER_REG_OP_ORDER, "sbb"},
    {0x19, OPER_REG_OP_ORDER, "sbb"},
    {0x1A, BYTE_REG_OPER_OP_ORDER, "sbb"},
    {0x1B, REG_OPER_OP_ORDER, "sbb"},
    {0x20, BYTE_OPER_REG_OP_ORDER, "and"},
    {0x21, OPER_REG_OP_ORDER, "and"},
    {0x22, BYTE_REG_OPER_OP_ORDER, "and"},
    {0x23, REG_OPER_OP_ORDER, "and"},
    {0x28, BYTE_OPER_REG_OP_ORDER, "sub"},
    {0x29, OPER_REG_OP_ORDER, "sub"},
    {0x2A, BYTE_REG_OPER_OP_ORDER, "sub"},
    {0x2B, REG_OPER_OP_ORDER, "sub"},
    {0x30, BYTE_OPER_REG_OP_ORDER, "xor"},
    {0x31, OPER_REG_OP_ORDER, "xor"},
    {0x32, BYTE_REG_OPER_OP_ORDER, "xor"},
    {0x33, REG_OPER_OP_ORDER, "xor"},
    {0x38, BYTE_OPER_REG_OP_ORDER, "cmp"},
    {0x39, OPER_REG_OP_ORDER, "cmp"},
    {0x3A, BYTE_REG_OPER_OP_ORDER, "cmp"},
    {0x3B, REG_OPER_OP_ORDER, "cmp"},
    {0x63, REG_OPER_OP_ORDER, "movsxl"},
    {0x84, BYTE_REG_OPER_OP_ORDER, "test"},
    {0x85, REG_OPER_OP_ORDER, "test"},
    {0x86, BYTE_REG_OPER_OP_ORDER, "xchg"},
    {0x87, REG_OPER_OP_ORDER, "xchg"},
    {0x88, BYTE_OPER_REG_OP_ORDER, "mov"},
    {0x89, OPER_REG_OP_ORDER, "mov"},
    {0x8A, BYTE_REG_OPER_OP_ORDER, "mov"},
    {0x8B, REG_OPER_OP_ORDER, "mov"},
    {0x8D, REG_OPER_OP_ORDER, "lea"},
    {-1, UNSET_OP_ORDER, ""}};

static const ByteMnemonic zero_operands_instr[] = {
    {0xC3, UNSET_OP_ORDER, "ret"},   {0xC9, UNSET_OP_ORDER, "leave"},
    {0xF4, UNSET_OP_ORDER, "hlt"},   {0xFC, UNSET_OP_ORDER, "cld"},
    {0xCC, UNSET_OP_ORDER, "int3"},  {0x60, UNSET_OP_ORDER, "pushad"},
    {0x61, UNSET_OP_ORDER, "popad"}, {0x9C, UNSET_OP_ORDER, "pushfd"},
    {0x9D, UNSET_OP_ORDER, "popfd"}, {0x9E, UNSET_OP_ORDER, "sahf"},
    {0x99, UNSET_OP_ORDER, "cdq"},   {0x9B, UNSET_OP_ORDER, "fwait"},
    {0xAB, UNSET_OP_ORDER, "stos"},  {0xA4, UNSET_OP_ORDER, "movs"},
    {0xA5, UNSET_OP_ORDER, "movs"},  {0xA6, UNSET_OP_ORDER, "cmps"},
    {0xA7, UNSET_OP_ORDER, "cmps"},  {-1, UNSET_OP_ORDER, ""}};

static const ByteMnemonic call_jump_instr[] = {{0xE8, UNSET_OP_ORDER, "call"},
                                               {0xE9, UNSET_OP_ORDER, "jmp"},
                                               {-1, UNSET_OP_ORDER, ""}};

static const ByteMnemonic short_immediate_instr[] = {
    {0x05, UNSET_OP_ORDER, "add"}, {0x0D, UNSET_OP_ORDER, "or"},
    {0x15, UNSET_OP_ORDER, "adc"}, {0x1D, UNSET_OP_ORDER, "sbb"},
    {0x25, UNSET_OP_ORDER, "and"}, {0x2D, UNSET_OP_ORDER, "sub"},
    {0x35, UNSET_OP_ORDER, "xor"}, {0x3D, UNSET_OP_ORDER, "cmp"},
    {-1, UNSET_OP_ORDER, ""}};

static const char* const conditional_code_suffix[] = {
    "o", "no", "c",  "nc", "z", "nz", "na", "a",
    "s", "ns", "pe", "po", "l", "ge", "le", "g"};

enum InstructionType {
  NO_INSTR,
  ZERO_OPERANDS_INSTR,
  TWO_OPERANDS_INSTR,
  JUMP_CONDITIONAL_SHORT_INSTR,
  REGISTER_INSTR,
  PUSHPOP_INSTR,  // Has implicit 64-bit operand size.
  MOVE_REG_INSTR,
  CALL_JUMP_INSTR,
  SHORT_IMMEDIATE_INSTR
};

enum Prefixes {
  ESCAPE_PREFIX = 0x0F,
  SEGMENT_FS_OVERRIDE_PREFIX = 0x64,
  OPERAND_SIZE_OVERRIDE_PREFIX = 0x66,
  ADDRESS_SIZE_OVERRIDE_PREFIX = 0x67,
  VEX3_PREFIX = 0xC4,
  VEX2_PREFIX = 0xC5,
  LOCK_PREFIX = 0xF0,
  REPNE_PREFIX = 0xF2,
  REP_PREFIX = 0xF3,
  REPEQ_PREFIX = REP_PREFIX
};

struct InstructionDesc {
  const char* mnem;
  InstructionType type;
  OperandType op_order_;
  bool byte_size_operation;  // Fixed 8-bit operation.
};

class InstructionTable {
 public:
  InstructionTable();
  const InstructionDesc& Get(uint8_t x) const { return instructions_[x]; }

 private:
  InstructionDesc instructions_[256];
  void Clear();
  void Init();
  void CopyTable(const ByteMnemonic bm[], InstructionType type);
  void SetTableRange(InstructionType type, uint8_t start, uint8_t end,
                     bool byte_size, const char* mnem);
  void AddJumpConditionalShort();
};

InstructionTable::InstructionTable() {
  Clear();
  Init();
}

void InstructionTable::Clear() {
  for (int i = 0; i < 256; i++) {
    instructions_[i].mnem = "(bad)";
    instructions_[i].type = NO_INSTR;
    instructions_[i].op_order_ = UNSET_OP_ORDER;
    instructions_[i].byte_size_operation = false;
  }
}

void InstructionTable::Init() {
  CopyTable(two_operands_instr, TWO_OPERANDS_INSTR);
  CopyTable(zero_operands_instr, ZERO_OPERANDS_INSTR);
  CopyTable(call_jump_instr, CALL_JUMP_INSTR);
  CopyTable(short_immediate_instr, SHORT_IMMEDIATE_INSTR);
  AddJumpConditionalShort();
  SetTableRange(PUSHPOP_INSTR, 0x50, 0x57, false, "push");
  SetTableRange(PUSHPOP_INSTR, 0x58, 0x5F, false, "pop");
  SetTableRange(MOVE_REG_INSTR, 0xB8, 0xBF, false, "mov");
}

void InstructionTable::CopyTable(const ByteMnemonic bm[],
                                 InstructionType type) {
  for (int i = 0; bm[i].b >= 0; i++) {
    InstructionDesc* id = &instructions_[bm[i].b];
    id->mnem = bm[i].mnem;
    OperandType op_order = bm[i].op_order_;
    id->op_order_ =
        static_cast<OperandType>(op_order & ~BYTE_SIZE_OPERAND_FLAG);
    DCHECK_EQ(NO_INSTR, id->type);  // Information not already entered
    id->type = type;
    id->byte_size_operation = ((op_order & BYTE_SIZE_OPERAND_FLAG) != 0);
  }
}

void InstructionTable::SetTableRange(InstructionType type, uint8_t start,
                                     uint8_t end, bool byte_size,
                                     const char* mnem) {
  for (uint8_t b = start; b <= end; b++) {
    InstructionDesc* id = &instructions_[b];
    DCHECK_EQ(NO_INSTR, id->type);  // Information not already entered
    id->mnem = mnem;
    id->type = type;
    id->byte_size_operation = byte_size;
  }
}

void InstructionTable::AddJumpConditionalShort() {
  for (uint8_t b = 0x70; b <= 0x7F; b++) {
    InstructionDesc* id = &instructions_[b];
    DCHECK_EQ(NO_INSTR, id->type);  // Information not already entered
    id->mnem = nullptr;             // Computed depending on condition code.
    id->type = JUMP_CONDITIONAL_SHORT_INSTR;
  }
}

namespace {
DEFINE_LAZY_LEAKY_OBJECT_GETTER(InstructionTable, GetInstructionTable)
}  // namespace

static const InstructionDesc cmov_instructions[16] = {
    {"cmovo", TWO_OPERANDS_INSTR, REG_OPER_OP_ORDER, false},
    {"cmovno", TWO_OPERANDS_INSTR, REG_OPER_OP_ORDER, false},
    {"cmovc", TWO_OPERANDS_INSTR, REG_OPER_OP_ORDER, false},
    {"cmovnc", TWO_OPERANDS_INSTR, REG_OPER_OP_ORDER, false},
    {"cmovz", TWO_OPERANDS_INSTR, REG_OPER_OP_ORDER, false},
    {"cmovnz", TWO_OPERANDS_INSTR, REG_OPER_OP_ORDER, false},
    {"cmovna", TWO_OPERANDS_INSTR, REG_OPER_OP_ORDER, false},
    {"cmova", TWO_OPERANDS_INSTR, REG_OPER_OP_ORDER, false},
    {"cmovs", TWO_OPERANDS_INSTR, REG_OPER_OP_ORDER, false},
    {"cmovns", TWO_OPERANDS_INSTR, REG_OPER_OP_ORDER, false},
    {"cmovpe", TWO_OPERANDS_INSTR, REG_OPER_OP_ORDER, false},
    {"cmovpo", TWO_OPERANDS_INSTR, REG_OPER_OP_ORDER, false},
    {"cmovl", TWO_OPERANDS_INSTR, REG_OPER_OP_ORDER, false},
    {"cmovge", TWO_OPERANDS_INSTR, REG_OPER_OP_ORDER, false},
    {"cmovle", TWO_OPERANDS_INSTR, REG_OPER_OP_ORDER, false},
    {"cmovg", TWO_OPERANDS_INSTR, REG_OPER_OP_ORDER, false}};

static const char* const cmp_pseudo_op[16] = {
    "eq",    "lt",  "le",  "unord", "neq",    "nlt", "nle", "ord",
    "eq_uq", "nge", "ngt", "false", "neq_oq", "ge",  "gt",  "true"};

namespace {
int8_t Imm8(const uint8_t* data) {
  return *reinterpret_cast<const int8_t*>(data);
}
uint8_t Imm8_U(const uint8_t* data) {
  return *reinterpret_cast<const uint8_t*>(data);
}
int16_t Imm16(const uint8_t* data) {
  return v8::base::ReadUnalignedValue<int16_t>(
      reinterpret_cast<v8::internal::Address>(data));
}
uint16_t Imm16_U(const uint8_t* data) {
  return v8::base::ReadUnalignedValue<uint16_t>(
      reinterpret_cast<v8::internal::Address>(data));
}
int32_t Imm32(const uint8_t* data) {
  return v8::base::ReadUnalignedValue<int32_t>(
      reinterpret_cast<v8::internal::Address>(data));
}
uint32_t Imm32_U(const uint8_t* data) {
  return v8::base::ReadUnalignedValue<uint32_t>(
      reinterpret_cast<v8::internal::Address>(data));
}
int64_t Imm64(const uint8_t* data) {
  return v8::base::ReadUnalignedValue<int64_t>(
      reinterpret_cast<v8::internal::Address>(data));
}
}  // namespace

//------------------------------------------------------------------------------
// DisassemblerX64 implementation.

// Forward-declare NameOfYMMRegister to keep its implementation with the
// NameConverter methods and register name arrays at bottom.
const char* NameOfYMMRegister(int reg);

// A new DisassemblerX64 object is created to disassemble each instruction.
// The object can only disassemble a single instruction.
class DisassemblerX64 {
 public:
  DisassemblerX64(const NameConverter& converter,
                  Disassembler::UnimplementedOpcodeAction unimplemented_action)
      : converter_(converter),
        tmp_buffer_pos_(0),
        abort_on_unimplemented_(unimplemented_action ==
                                Disassembler::kAbortOnUnimplementedOpcode),
        rex_(0),
        operand_size_(0),
        group_1_prefix_(0),
        segment_prefix_(0),
        address_size_prefix_(0),
        vex_byte0_(0),
        vex_byte1_(0),
        vex_byte2_(0),
        byte_size_operand_(false),
        instruction_table_(GetInstructionTable()) {
    tmp_buffer_[0] = '\0';
  }

  // Writes one disassembled instruction into 'buffer' (0-terminated).
  // Returns the length of the disassembled machine instruction in bytes.
  int InstructionDecode(v8::base::Vector<char> buffer, uint8_t* instruction);

 private:
  enum OperandSize {
    OPERAND_BYTE_SIZE = 0,
    OPERAND_WORD_SIZE = 1,
    OPERAND_DOUBLEWORD_SIZE = 2,
    OPERAND_QUADWORD_SIZE = 3
  };

  const NameConverter& converter_;
  v8::base::EmbeddedVector<char, 128> tmp_buffer_;
  unsigned int tmp_buffer_pos_;
  bool abort_on_unimplemented_;
  // Prefixes parsed.
  uint8_t rex_;
  uint8_t operand_size_;         // 0x66 or (without group 3 prefix) 0x0.
  uint8_t group_1_prefix_;       // 0xF2, 0xF3, or (without group 1 prefix) 0.
  uint8_t segment_prefix_;       // 0x64 or (without group 2 prefix) 0.
  uint8_t address_size_prefix_;  // 0x67 or (without group 4 prefix) 0.
  uint8_t vex_byte0_;            // 0xC4 or 0xC5.
  uint8_t vex_byte1_;
  uint8_t vex_byte2_;  // only for 3 bytes vex prefix.
  // Byte size operand override.
  bool byte_size_operand_;
  const InstructionTable* const instruction_table_;

  void setRex(uint8_t rex) {
    DCHECK_EQ(0x40, rex & 0xF0);
    rex_ = rex;
  }

  bool rex() { return rex_ != 0; }

  bool rex_b() { return (rex_ & 0x01) != 0; }

  // Actual number of base register given the low bits and the rex.b state.
  int base_reg(int low_bits) { return low_bits | ((rex_ & 0x01) << 3); }

  bool rex_x() { return (rex_ & 0x02) != 0; }

  bool rex_r() { return (rex_ & 0x04) != 0; }

  bool rex_w() { return (rex_ & 0x08) != 0; }

  bool vex_w() {
    DCHECK(vex_byte0_ == VEX3_PREFIX || vex_byte0_ == VEX2_PREFIX);
    return vex_byte0_ == VEX3_PREFIX ? (vex_byte2_ & 0x80) != 0 : false;
  }

  bool vex_128() {
    DCHECK(vex_byte0_ == VEX3_PREFIX || vex_byte0_ == VEX2_PREFIX);
    uint8_t checked = vex_byte0_ == VEX3_PREFIX ? vex_byte2_ : vex_byte1_;
    return (checked & 4) == 0;
  }

  bool vex_256() const {
    DCHECK(vex_byte0_ == VEX3_PREFIX || vex_byte0_ == VEX2_PREFIX);
    uint8_t checked = vex_byte0_ == VEX3_PREFIX ? vex_byte2_ : vex_byte1_;
    return (checked & 4) != 0;
  }

  bool vex_none() {
    DCHECK(vex_byte0_ == VEX3_PREFIX || vex_byte0_ == VEX2_PREFIX);
    uint8_t checked = vex_byte0_ == VEX3_PREFIX ? vex_byte2_ : vex_byte1_;
    return (checked & 3) == 0;
  }

  bool vex_66() {
    DCHECK(vex_byte0_ == VEX3_PREFIX || vex_byte0_ == VEX2_PREFIX);
    uint8_t checked = vex_byte0_ == VEX3_PREFIX ? vex_byte2_ : vex_byte1_;
    return (checked & 3) == 1;
  }

  bool vex_f3() {
    DCHECK(vex_byte0_ == VEX3_PREFIX || vex_byte0_ == VEX2_PREFIX);
    uint8_t checked = vex_byte0_ == VEX3_PREFIX ? vex_byte2_ : vex_byte1_;
    return (checked & 3) == 2;
  }

  bool vex_f2() {
    DCHECK(vex_byte0_ == VEX3_PREFIX || vex_byte0_ == VEX2_PREFIX);
    uint8_t checked = vex_byte0_ == VEX3_PREFIX ? vex_byte2_ : vex_byte1_;
    return (checked & 3) == 3;
  }

  bool vex_0f() {
    if (vex_byte0_ == VEX2_PREFIX) return true;
    return (vex_byte1_ & 3) == 1;
  }

  bool vex_0f38() {
    if (vex_byte0_ == VEX2_PREFIX) return false;
    return (vex_byte1_ & 3) == 2;
  }

  bool vex_0f3a() {
    if (vex_byte0_ == VEX2_PREFIX) return false;
    return (vex_byte1_ & 3) == 3;
  }

  int vex_vreg() {
    DCHECK(vex_byte0_ == VEX3_PREFIX || vex_byte0_ == VEX2_PREFIX);
    uint8_t checked = vex_byte0_ == VEX3_PREFIX ? vex_byte2_ : vex_byte1_;
    return ~(checked >> 3) & 0xF;
  }

  OperandSize operand_size() {
    if (byte_size_operand_) return OPERAND_BYTE_SIZE;
    if (rex_w()) return OPERAND_QUADWORD_SIZE;
    if (operand_size_ != 0) return OPERAND_WORD_SIZE;
    return OPERAND_DOUBLEWORD_SIZE;
  }

  char operand_size_code() { return "bwlq"[operand_size()]; }

  char float_size_code() { return "sd"[rex_w()]; }

  const char* NameOfCPURegister(int reg) const {
    return converter_.NameOfCPURegister(reg);
  }

  const char* NameOfByteCPURegister(int reg) const {
    return converter_.NameOfByteCPURegister(reg);
  }

  const char* NameOfXMMRegister(int reg) const {
    return converter_.NameOfXMMRegister(reg);
  }

  const char* NameOfAVXRegister(int reg) const {
    if (vex_256()) {
      return NameOfYMMRegister(reg);
    } else {
      return converter_.NameOfXMMRegister(reg);
    }
  }

  const char* NameOfAddress(uint8_t* addr) const {
    return converter_.NameOfAddress(addr);
  }

  // Disassembler helper functions.
  void get_modrm(uint8_t data, int* mod, int* regop, int* rm) {
    *mod = (data >> 6) & 3;
    *regop = ((data & 0x38) >> 3) | (rex_r() ? 8 : 0);
    *rm = (data & 7) | (rex_b() ? 8 : 0);
  }

  void get_sib(uint8_t data, int* scale, int* index, int* base) {
    *scale = (data >> 6) & 3;
    *index = ((data >> 3) & 7) | (rex_x() ? 8 : 0);
    *base = (data & 7) | (rex_b() ? 8 : 0);
  }

  using RegisterNameMapping = const char* (DisassemblerX64::*)(int reg) const;

  void TryAppendRootRelativeName(int offset);
  int PrintRightOperandHelper(uint8_t* modrmp, RegisterNameMapping);
  int PrintRightOperand(uint8_t* modrmp);
  int PrintRightByteOperand(uint8_t* modrmp);
  int PrintRightXMMOperand(uint8_t* modrmp);
  int PrintRightAVXOperand(uint8_t* modrmp);
  int PrintOperands(const char* mnem, OperandType op_order, uint8_t* data);
  int PrintImmediate(uint8_t* data, OperandSize size);
  int PrintImmediateOp(uint8_t* data);
  const char* TwoByteMnemonic(uint8_t opcode);
  int TwoByteOpcodeInstruction(uint8_t* data);
  int ThreeByteOpcodeInstruction(uint8_t* data);
  int F6F7Instruction(uint8_t* data);
  int ShiftInstruction(uint8_t* data);
  int JumpShort(uint8_t* data);
  int JumpConditional(uint8_t* data);
  int JumpConditionalShort(uint8_t* data);
  int SetCC(uint8_t* data);
  int FPUInstruction(uint8_t* data);
  int MemoryFPUInstruction(int escape_opcode, int regop, uint8_t* modrm_start);
  int RegisterFPUInstruction(int escape_opcode, uint8_t modrm_byte);
  int AVXInstruction(uint8_t* data);
  PRINTF_FORMAT(2, 3) void AppendToBuffer(const char* format, ...);

  void UnimplementedInstruction() {
    if (abort_on_unimplemented_) {
      FATAL("'Unimplemented Instruction'");
    } else {
      AppendToBuffer("'Unimplemented Instruction'");
    }
  }
};

void DisassemblerX64::AppendToBuffer(const char* format, ...) {
  v8::base::Vector<char> buf = tmp_buffer_ + tmp_buffer_pos_;
  va_list args;
  va_start(args, format);
  int result = v8::base::VSNPrintF(buf, format, args);
  va_end(args);
  tmp_buffer_pos_ += result;
}

void DisassemblerX64::TryAppendRootRelativeName(int offset) {
  const char* maybe_name = converter_.RootRelativeName(offset);
  if (maybe_name != nullptr) AppendToBuffer(" (%s)", maybe_name);
}

int DisassemblerX64::PrintRightOperandHelper(
    uint8_t* modrmp, RegisterNameMapping direct_register_name) {
  int mod, regop, rm;
  get_modrm(*modrmp, &mod, &regop, &rm);
  RegisterNameMapping register_name =
      (mod == 3) ? direct_register_name : &DisassemblerX64::NameOfCPURegister;
  switch (mod) {
    case 0:
      if ((rm & 7) == 5) {
        AppendToBuffer("[rip+0x%x]", Imm32(modrmp + 1));
        return 5;
      } else if ((rm & 7) == 4) {
        // Codes for SIB byte.
        uint8_t sib = *(modrmp + 1);
        int scale, index, base;
        get_sib(sib, &scale, &index, &base);
        if (index == 4 && (base & 7) == 4 && scale == 0 /*times_1*/) {
          // index == rsp means no index. Only use sib byte with no index for
          // rsp and r12 base.
          AppendToBuffer("[%s]", NameOfCPURegister(base));
          return 2;
        } else if (base == 5) {
          // base == rbp means no base register (when mod == 0).
          int32_t disp = Imm32(modrmp + 2);
          AppendToBuffer("[%s*%d%s0x%x]", NameOfCPURegister(index), 1 << scale,
                         disp < 0 ? "-" : "+", disp < 0 ? -disp : disp);
          return 6;
        } else if (index != 4 && base != 5) {
          // [base+index*scale]
          AppendToBuffer("[%s+%s*%d]", NameOfCPURegister(base),
                         NameOfCPURegister(index), 1 << scale);
          return 2;
        } else {
          UnimplementedInstruction();
          return 1;
        }
      } else {
        AppendToBuffer("[%s]", NameOfCPURegister(rm));
        return 1;
      }
    case 1:  // fall through
    case 2:
      if ((rm & 7) == 4) {
        uint8_t sib = *(modrmp + 1);
        int scale, index, base;
        get_sib(sib, &scale, &index, &base);
        int disp = (mod == 2) ? Imm32(modrmp + 2) : Imm8(modrmp + 2);
        if (index == 4 && (base & 7) == 4 && scale == 0 /*times_1*/) {
          AppendToBuffer("[%s%s0x%x]", NameOfCPURegister(base),
                         disp < 0 ? "-" : "+", disp < 0 ? -disp : disp);
        } else {
          AppendToBuffer("[%s+%s*%d%s0x%x]", NameOfCPURegister(base),
                         NameOfCPURegister(index), 1 << scale,
                         disp < 0 ? "-" : "+", disp < 0 ? -disp : disp);
        }
        return mod == 2 ? 6 : 3;
      } else {
        // No sib.
        int disp = (mod == 2) ? Imm32(modrmp + 1) : Imm8(modrmp + 1);
        AppendToBuffer("[%s%s0x%x]", NameOfCPURegister(rm),
                       disp < 0 ? "-" : "+", disp < 0 ? -disp : disp);
        if (rm == i::kRootRegister.code()) {
          // For root-relative accesses, try to append a description.
          TryAppendRootRelativeName(disp);
        }
        return (mod == 2) ? 5 : 2;
      }
    case 3:
      AppendToBuffer("%s", (this->*register_name)(rm));
      return 1;
    default:
      UnimplementedInstruction();
      return 1;
  }
  UNREACHABLE();
}

int DisassemblerX64::PrintImmediate(uint8_t* data, OperandSize size) {
  int64_t value;
  int count;
  switch (size) {
    case OPERAND_BYTE_SIZE:
      value = *data;
      count = 1;
      break;
    case OPERAND_WORD_SIZE:
      value = Imm16(data);
      count = 2;
      break;
    case OPERAND_DOUBLEWORD_SIZE:
      value = Imm32_U(data);
      count = 4;
      break;
    case OPERAND_QUADWORD_SIZE:
      value = Imm32(data);
      count = 4;
      break;
    default:
      UNREACHABLE();
  }
  AppendToBuffer("%" PRIx64, value);
  return count;
}

int DisassemblerX64::PrintRightOperand(uint8_t* modrmp) {
  return PrintRightOperandHelper(modrmp, &DisassemblerX64::NameOfCPURegister);
}

int DisassemblerX64::PrintRightByteOperand(uint8_t* modrmp) {
  return PrintRightOperandHelper(modrmp,
                                 &DisassemblerX64::NameOfByteCPURegister);
}

int DisassemblerX64::PrintRightXMMOperand(uint8_t* modrmp) {
  return PrintRightOperandHelper(modrmp, &DisassemblerX64::NameOfXMMRegister);
}

int DisassemblerX64::PrintRightAVXOperand(uint8_t* modrmp) {
  return PrintRightOperandHelper(modrmp, &DisassemblerX64::NameOfAVXRegister);
}

// Returns number of bytes used including the current *data.
// Writes instruction's mnemonic, left and right operands to 'tmp_buffer_'.
int DisassemblerX64::PrintOperands(const char* mnem, OperandType op_order,
                                   uint8_t* data) {
  uint8_t modrm = *data;
  int mod, regop, rm;
  get_modrm(modrm, &mod, &regop, &rm);
  int advance = 0;
  const char* register_name = byte_size_operand_ ? NameOfByteCPURegister(regop)
                                                 : NameOfCPURegister(regop);
  switch (op_order) {
    case REG_OPER_OP_ORDER: {
      AppendToBuffer("%s%c %s,", mnem, operand_size_code(), register_name);
      advance = byte_size_operand_ ? PrintRightByteOperand(data)
                                   : PrintRightOperand(data);
      break;
    }
    case OPER_REG_OP_ORDER: {
      AppendToBuffer("%s%c ", mnem, operand_size_code());
      advance = byte_size_operand_ ? PrintRightByteOperand(data)
                                   : PrintRightOperand(data);
      AppendToBuffer(",%s", register_name);
      break;
    }
    case XMMREG_XMMOPER_OP_ORDER: {
      AppendToBuffer("%s %s,", mnem, NameOfXMMRegister(regop));
      advance = PrintRightXMMOperand(data);
      break;
    }
    case XMMOPER_XMMREG_OP_ORDER: {
      AppendToBuffer("%s ", mnem);
      advance = PrintRightXMMOperand(data);
      AppendToBuffer(",%s", NameOfXMMRegister(regop));
      break;
    }
    case OPER_XMMREG_OP_ORDER: {
      AppendToBuffer("%s ", mnem);
      advance = PrintRightOperand(data);
      AppendToBuffer(",%s", NameOfXMMRegister(regop));
      break;
    }
    case XMMREG_OPER_OP_ORDER: {
      AppendToBuffer("%s %s,", mnem, NameOfXMMRegister(regop));
      advance = PrintRightOperand(data);
      break;
    }
    default:
      UNREACHABLE();
  }
  return advance;
}

// Returns number of bytes used by machine instruction, including *data byte.
// Writes immediate instructions to 'tmp_buffer_'.
int DisassemblerX64::PrintImmediateOp(uint8_t* data) {
  DCHECK(*data == 0x80 || *data == 0x81 || *data == 0x83);
  bool byte_size_immediate = *data != 0x81;
  uint8_t modrm = *(data + 1);
  int mod, regop, rm;
  get_modrm(modrm, &mod, &regop, &rm);
  const char* mnem = "Imm???";
  switch (regop) {
    case 0:
      mnem = "add";
      break;
    case 1:
      mnem = "or";
      break;
    case 2:
      mnem = "adc";
      break;
    case 3:
      mnem = "sbb";
      break;
    case 4:
      mnem = "and";
      break;
    case 5:
      mnem = "sub";
      break;
    case 6:
      mnem = "xor";
      break;
    case 7:
      mnem = "cmp";
      break;
    default:
      UnimplementedInstruction();
  }
  AppendToBuffer("%s%c ", mnem, operand_size_code());
  int count = byte_size_operand_ ? PrintRightByteOperand(data + 1)
                                 : PrintRightOperand(data + 1);
  AppendToBuffer(",0x");
  OperandSize immediate_size =
      byte_size_immediate ? OPERAND_BYTE_SIZE : operand_size();
  count += PrintImmediate(data + 1 + count, immediate_size);
  return 1 + count;
}

// Returns number of bytes used, including *data.
int DisassemblerX64::F6F7Instruction(uint8_t* data) {
  DCHECK(*data == 0xF7 || *data == 0xF6);
  uint8_t modrm = *(data + 1);
  int mod, regop, rm;
  get_modrm(modrm, &mod, &regop, &rm);
  if (regop != 0) {
    const char* mnem = nullptr;
    switch (regop) {
      case 2:
        mnem = "not";
        break;
      case 3:
        mnem = "neg";
        break;
      case 4:
        mnem = "mul";
        break;
      case 5:
        mnem = "imul";
        break;
      case 6:
        mnem = "div";
        break;
      case 7:
        mnem = "idiv";
        break;
      default:
        UnimplementedInstruction();
    }
    if (mod == 3) {
      AppendToBuffer("%s%c %s", mnem, operand_size_code(),
                     NameOfCPURegister(rm));
      return 2;
    } else if (mod == 1 ||
               mod == 2) {  // Byte displacement or 32-bit displacement
      AppendToBuffer("%s%c ", mnem, operand_size_code());
      int count = PrintRightOperand(data + 1);  // Use name of 64-bit register.
      return 1 + count;
    } else {
      UnimplementedInstruction();
      return 2;
    }
  } else if (regop == 0) {
    AppendToBuffer("test%c ", operand_size_code());
    int count = PrintRightOperand(data + 1);  // Use name of 64-bit register.
    AppendToBuffer(",0x");
    count += PrintImmediate(data + 1 + count, operand_size());
    return 1 + count;
  } else {
    UnimplementedInstruction();
    return 2;
  }
}

int DisassemblerX64::ShiftInstruction(uint8_t* data) {
  uint8_t op = *data & (~1);
  int count = 1;
  if (op != 0xD0 && op != 0xD2 && op != 0xC0) {
    UnimplementedInstruction();
    return count;
  }
  // Print mneumonic.
  {
    uint8_t modrm = *(data + count);
    int mod, regop, rm;
    get_modrm(modrm, &mod, &regop, &rm);
    regop &= 0x7;  // The REX.R bit does not affect the operation.
    const char* mnem = nullptr;
    switch (regop) {
      case 0:
        mnem = "rol";
        break;
      case 1:
        mnem = "ror";
        break;
      case 2:
        mnem = "rcl";
        break;
      case 3:
        mnem = "rcr";
        break;
      case 4:
        mnem = "shl";
        break;
      case 5:
        mnem = "shr";
        break;
      case 7:
        mnem = "sar";
        break;
      default:
        UnimplementedInstruction();
        return count + 1;
    }
    DCHECK_NOT_NULL(mnem);
    AppendToBuffer("%s%c ", mnem, operand_size_code());
  }
  count += PrintRightOperand(data + count);
  if (op == 0xD2) {
    AppendToBuffer(", cl");
  } else {
    int imm8 = -1;
    if (op == 0xD0) {
      imm8 = 1;
    } else {
      DCHECK_EQ(0xC0, op);
      imm8 = *(data + count);
      count++;
    }
    AppendToBuffer(", %d", imm8);
  }
  return count;
}

// Returns number of bytes used, including *data.
int DisassemblerX64::JumpShort(uint8_t* data) {
  DCHECK_EQ(0xEB, *data);
  uint8_t b = *(data + 1);
  uint8_t* dest = data + static_cast<int8_t>(b) + 2;
  AppendToBuffer("jmp %s", NameOfAddress(dest));
  return 2;
}

// Returns number of bytes used, including *data.
int DisassemblerX64::JumpConditional(uint8_t* data) {
  DCHECK_EQ(0x0F, *data);
  uint8_t cond = *(data + 1) & 0x0F;
  uint8_t* dest = data + Imm32(data + 2) + 6;
  const char* mnem = conditional_code_suffix[cond];
  AppendToBuffer("j%s %s", mnem, NameOfAddress(dest));
  return 6;  // includes 0x0F
}

// Returns number of bytes used, including *data.
int DisassemblerX64::JumpConditionalShort(uint8_t* data) {
  uint8_t cond = *data & 0x0F;
  uint8_t b = *(data + 1);
  uint8_t* dest = data + static_cast<int8_t>(b) + 2;
  const char* mnem = conditional_code_suffix[cond];
  AppendToBuffer("j%s %s", mnem, NameOfAddress(dest));
  return 2;
}

// Returns number of bytes used, including *data.
int DisassemblerX64::SetCC(uint8_t* data) {
  DCHECK_EQ(0x0F, *data);
  uint8_t cond = *(data + 1) & 0x0F;
  const char* mnem = conditional_code_suffix[cond];
  AppendToBuffer("set%s%c ", mnem, operand_size_code());
  PrintRightByteOperand(data + 2);
  return 3;  // includes 0x0F
}

const char* sf_str[4] = {"", "rl", "ra", "ll"};

int DisassemblerX64::AVXInstruction(uint8_t* data) {
  uint8_t opcode = *data;
  uint8_t* current = data + 1;
  if (vex_66() && vex_0f38()) {
    int mod, regop, rm, vvvv = vex_vreg();
    get_modrm(*current, &mod, &regop, &rm);
    switch (opcode) {
      case 0x13:
        AppendToBuffer("vcvtph2ps %s,", NameOfAVXRegister(regop));
        current += PrintRightXMMOperand(current);
        break;
      case 0x18:
        AppendToBuffer("vbroadcastss %s,", NameOfAVXRegister(regop));
        current += PrintRightXMMOperand(current);
        break;
      case 0x19:
        AppendToBuffer("vbroadcastsd %s,", NameOfAVXRegister(regop));
        current += PrintRightXMMOperand(current);
        break;
      case 0xF7:
        AppendToBuffer("shlx%c %s,", operand_size_code(),
                       NameOfCPURegister(regop));
        current += PrintRightOperand(current);
        AppendToBuffer(",%s", NameOfCPURegister(vvvv));
        break;
      case 0x50:
        AppendToBuffer("vpdpbusd %s,%s,", NameOfAVXRegister(regop),
                       NameOfAVXRegister(vvvv));
        current += PrintRightAVXOperand(current);
        break;
#define DECLARE_SSE_AVX_DIS_CASE(instruction, notUsed1, notUsed2, notUsed3, \
                                 opcode)                                    \
  case 0x##opcode: {                                                        \
    AppendToBuffer("v" #instruction " %s,%s,", NameOfAVXRegister(regop),    \
                   NameOfAVXRegister(vvvv));                                \
    current += PrintRightAVXOperand(current);                               \
    break;                                                                  \
  }

        SSSE3_INSTRUCTION_LIST(DECLARE_SSE_AVX_DIS_CASE)
        SSE4_INSTRUCTION_LIST(DECLARE_SSE_AVX_DIS_CASE)
        SSE4_2_INSTRUCTION_LIST(DECLARE_SSE_AVX_DIS_CASE)
#undef DECLARE_SSE_AVX_DIS_CASE

#define DECLARE_SSE_UNOP_AVX_DIS_CASE(instruction, notUsed1, notUsed2, \
                                      notUsed3, opcode)                \
  case 0x##opcode: {                                                   \
    AppendToBuffer("v" #instruction " %s,", NameOfAVXRegister(regop)); \
    current += PrintRightAVXOperand(current);                          \
    break;                                                             \
  }
        SSSE3_UNOP_INSTRUCTION_LIST(DECLARE_SSE_UNOP_AVX_DIS_CASE)
        SSE4_UNOP_INSTRUCTION_LIST(DECLARE_SSE_UNOP_AVX_DIS_CASE)
#undef DECLARE_SSE_UNOP_AVX_DIS_CASE

#define DISASSEMBLE_AVX2_BROADCAST(instruction, _1, _2, _3, code)     \
  case 0x##code:                                                      \
    AppendToBuffer("" #instruction " %s,", NameOfAVXRegister(regop)); \
    current += PrintRightXMMOperand(current);                         \
    break;
        AVX2_BROADCAST_LIST(DISASSEMBLE_AVX2_BROADCAST)
#undef DISASSEMBLE_AVX2_BROADCAST

      default: {
#define DECLARE_FMA_DISASM(instruction, _1, _2, _3, _4, code)        \
  case 0x##code: {                                                   \
    AppendToBuffer(#instruction " %s,%s,", NameOfAVXRegister(regop), \
                   NameOfAVXRegister(vvvv));                         \
    current += PrintRightAVXOperand(current);                        \
    break;                                                           \
  }
        // Handle all the fma instructions here in the default branch since they
        // have the same opcodes but differ by rex_w.
        if (rex_w()) {
          switch (opcode) {
            FMA_SD_INSTRUCTION_LIST(DECLARE_FMA_DISASM)
```