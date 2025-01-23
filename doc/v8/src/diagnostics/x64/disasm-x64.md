Response: My thinking process to summarize the C++ code goes through these stages:

1. **Identify the core purpose from the filename and path:** The filename `disasm-x64.cc` and the path `v8/src/diagnostics/x64/` strongly suggest this code is related to disassembling x64 instructions for debugging/diagnostics within the V8 JavaScript engine. The `diagnostics` part is a key indicator.

2. **Scan for high-level structural elements:** I look for namespaces (`disasm`), classes (`DisassemblerX64`, `InstructionTable`), structs (`ByteMnemonic`, `InstructionDesc`), enums (`OperandType`, `InstructionType`, `Prefixes`), and global-like constants (`two_operands_instr`, `zero_operands_instr`, etc.). These provide the basic building blocks of the code's organization.

3. **Analyze the key data structures:**
    * `ByteMnemonic`: This clearly links a byte value (opcode) to a mnemonic string (human-readable instruction name) and an `OperandType`. This is the foundation for looking up instruction names.
    * `OperandType`:  This enum describes the order and type of operands for an instruction (register-operand, operand-register, byte operands, XMM registers, etc.).
    * `InstructionType`:  This enum categorizes instructions based on the number or type of operands they take (zero-operand, two-operand, jump, register, etc.).
    * `InstructionDesc`: This bundles the mnemonic, instruction type, operand order, and a flag for byte-sized operations.
    * `InstructionTable`: This class seems to be a lookup table (likely an array) that maps opcodes (bytes) to their `InstructionDesc`. The `Init()` and `CopyTable()` methods suggest how this table is populated.

4. **Focus on the main class: `DisassemblerX64`:** This class likely contains the core logic for disassembling instructions. I look at its members and methods:
    * **Constructor:** Takes a `NameConverter` and an `UnimplementedOpcodeAction`. This suggests it needs a way to convert registers/addresses to names and handle unknown opcodes.
    * **`InstructionDecode()`:** This is the most important method. It takes a buffer and an instruction (as a byte array) and likely fills the buffer with the disassembled representation. This is the entry point for the disassembling process.
    * **Private members:**  Lots of flags and variables to store parsed information (prefixes, operand sizes, VEX bytes, REX byte). This hints at the complexity of the x64 instruction set.
    * **Helper methods:**  Methods like `get_modrm`, `get_sib`, `PrintRightOperand`, `PrintImmediate`, `PrintOperands`, and various instruction-specific printing methods (`TwoByteOpcodeInstruction`, `AVXInstruction`, `FPUInstruction`, etc.) suggest a step-by-step process of parsing and formatting the instruction.

5. **Infer the overall flow:**  The `InstructionDecode` method likely does the following:
    * Parses prefixes (REX, operand size, segment, VEX).
    * Looks up the main opcode in the `InstructionTable`.
    * Based on the `InstructionType` and `OperandType`, calls appropriate helper functions to:
        * Decode ModR/M and SIB bytes to determine operands (registers, memory addresses, immediates).
        * Format the output string, including the mnemonic and operands.

6. **Look for connections to JavaScript:** The code resides within the V8 engine, so its purpose is to help understand the machine code generated when JavaScript is executed. It's used for debugging, profiling, and potentially optimizing the generated code. It doesn't *execute* JavaScript, but it provides insight into its low-level implementation.

7. **Formulate the summary:** Based on the above analysis, I construct the summary, highlighting:
    * The core function of disassembling x64 instructions.
    * Its location within the V8 engine and its purpose for diagnostics.
    * Key data structures used for instruction lookup and operand handling.
    * The main class responsible for the disassembling logic.
    * The relationship to JavaScript (analyzing the generated machine code).

8. **Create the JavaScript example (if requested):** To illustrate the connection to JavaScript, I need to show how the disassembled output relates to a JavaScript snippet. A simple function is a good example. I would:
    * Write a short JavaScript function.
    * Explain that V8 compiles this to machine code.
    * Hypothetically show a snippet of the disassembled output that might correspond to the JavaScript function (e.g., a `mov` instruction to load a value into a register, an `add` instruction for addition). *Crucially, I don't need to actually run the disassembler here, just illustrate the concept.*

By following these steps, I can dissect the C++ code and arrive at a comprehensive and accurate summary of its functionality and its relation to JavaScript. The key is to move from the general purpose down to specific data structures and methods, and then back up to understand the overall system.
这个C++源代码文件 `disasm-x64.cc`，作为V8 JavaScript引擎的一部分，主要功能是 **将x64架构的机器码指令反汇编成可读的汇编代码**。

以下是更详细的归纳：

* **反汇编核心:**  该文件包含了 `DisassemblerX64` 类，这个类是反汇编器的核心实现。它的主要任务是读取一段x64机器码的字节序列，并将其翻译成对应的汇编指令，包括指令的操作码和操作数。

* **指令信息存储:**  代码中定义了多个静态常量数组（如 `two_operands_instr`, `zero_operands_instr` 等）和结构体 (`ByteMnemonic`, `InstructionDesc`)，用于存储x64指令集的各种信息，包括：
    * **操作码 (Opcode):** 指令的字节表示。
    * **助记符 (Mnemonic):**  指令的文本名称 (例如 "mov", "add", "jmp")。
    * **操作数类型 (OperandType):**  指令操作数的顺序和类型（例如寄存器到内存，内存到寄存器，立即数等）。
    * **指令类型 (InstructionType):**  指令的分类，例如零操作数指令，双操作数指令，跳转指令等。

* **指令查找表:** `InstructionTable` 类用于创建一个指令查找表，将操作码字节映射到 `InstructionDesc` 结构体，方便快速查找指令信息。

* **前缀处理:**  x64指令可以带有各种前缀（如 REX, 操作数大小覆盖, 地址大小覆盖, VEX 等），反汇编器需要正确解析和处理这些前缀，以确定指令的完整含义。

* **操作数格式化:**  `DisassemblerX64` 类中的 `PrintOperands`、`PrintRightOperand` 等方法负责将指令的操作数（寄存器、内存地址、立即数）格式化成易于理解的文本表示。

* **VEX 指令支持:**  代码中专门处理了 AVX (Advanced Vector Extensions) 指令，这些指令使用 VEX 前缀，用于进行SIMD (Single Instruction, Multiple Data) 操作。

* **FPU 指令支持:**  代码也包含了对 x87 浮点单元 (FPU) 指令的反汇编支持。

* **与 `NameConverter` 配合:**  `DisassemblerX64` 类依赖于一个 `NameConverter` 对象，这个对象负责将寄存器编号、内存地址等转换为更具可读性的名称（例如将寄存器编号转换为 "rax", "rbx" 等）。

**它与JavaScript的功能的关系：**

V8引擎负责执行JavaScript代码。为了进行调试、性能分析或者理解V8引擎的内部工作原理，开发者需要能够查看V8生成的机器码。 `disasm-x64.cc` 中的反汇编器就是为了这个目的而存在的。

当V8编译JavaScript代码时，它会生成一系列的x64机器码指令。  `disasm-x64.cc` 提供的反汇编功能可以将这些机器码指令转换成人类可读的汇编代码，帮助开发者理解V8是如何将JavaScript代码翻译成机器指令执行的。

**JavaScript 举例说明:**

假设有以下简单的 JavaScript 函数：

```javascript
function add(a, b) {
  return a + b;
}
```

当V8引擎编译这个函数时，可能会生成类似以下的 x64 机器码（这只是一个简化的例子，实际生成的代码会更复杂）：

```
55                push   rbp
48 89 e5          mov    rbp, rsp
8b 45 08          mov    eax, DWORD PTR [rbp+0x8]  // Load argument 'a'
03 45 10          add    eax, DWORD PTR [rbp+0x10] // Add argument 'b'
5d                pop    rbp
c3                ret
```

`disasm-x64.cc` 文件的功能就是将上述的机器码字节序列 (例如 `55 48 89 e5 8b 45 08 03 45 10 5d c3`) 转换成右侧可读的汇编指令。

**在V8内部，你可能会看到类似这样的使用场景（伪代码）：**

```c++
// 假设 'code_start' 是指向已编译的 JavaScript 函数的机器码起始地址
uint8_t* current_instruction = code_start;
DisassemblerX64 disassembler(name_converter, Disassembler::kNoAbortOnUnimplementedOpcode);
char buffer[256]; // 用于存储反汇编结果

while (current_instruction < code_end) {
  v8::base::Vector<char> output_buffer(buffer, sizeof(buffer));
  int instruction_length = disassembler.InstructionDecode(output_buffer, current_instruction);
  printf("%p  %s\n", current_instruction, buffer); // 打印指令地址和反汇编结果
  current_instruction += instruction_length;
}
```

这段伪代码展示了如何使用 `DisassemblerX64` 来遍历一段机器码，并将其反汇编成字符串。这些反汇编后的字符串可以被打印出来，供开发者查看。

总结来说，`v8/src/diagnostics/x64/disasm-x64.cc` 是 V8 引擎中负责将 x64 机器码转换为可读汇编代码的关键组件，它对于理解 V8 如何执行 JavaScript 代码至关重要。

### 提示词
```
这是目录为v8/src/diagnostics/x64/disasm-x64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
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
            FMA_PD_INSTRUCTION_LIST(DECLARE_FMA_DISASM)
            default: {
              UnimplementedInstruction();
            }
          }
        } else {
          switch (opcode) {
            FMA_SS_INSTRUCTION_LIST(DECLARE_FMA_DISASM)
            FMA_PS_INSTRUCTION_LIST(DECLARE_FMA_DISASM)
            default: {
              UnimplementedInstruction();
            }
          }
        }
#undef DECLARE_FMA_DISASM
      }
    }
  } else if (vex_66() && vex_0f3a()) {
    int mod, regop, rm, vvvv = vex_vreg();
    get_modrm(*current, &mod, &regop, &rm);
    switch (opcode) {
      case 0x00:
        AppendToBuffer("vpermq %s,", NameOfAVXRegister(regop));
        current += PrintRightAVXOperand(current);
        AppendToBuffer(",0x%x", *current++);
        break;
      case 0x06:
        AppendToBuffer("vperm2f128 %s,%s,", NameOfAVXRegister(regop),
                       NameOfAVXRegister(vvvv));
        current += PrintRightAVXOperand(current);
        AppendToBuffer(",0x%x", *current++);
        break;
      case 0x08:
        AppendToBuffer("vroundps %s,", NameOfAVXRegister(regop));
        current += PrintRightAVXOperand(current);
        AppendToBuffer(",0x%x", *current++);
        break;
      case 0x09:
        AppendToBuffer("vroundpd %s,", NameOfAVXRegister(regop));
        current += PrintRightAVXOperand(current);
        AppendToBuffer(",0x%x", *current++);
        break;
      case 0x0A:
        AppendToBuffer("vroundss %s,%s,", NameOfAVXRegister(regop),
                       NameOfAVXRegister(vvvv));
        current += PrintRightAVXOperand(current);
        AppendToBuffer(",0x%x", *current++);
        break;
      case 0x0B:
        AppendToBuffer("vroundsd %s,%s,", NameOfAVXRegister(regop),
                       NameOfAVXRegister(vvvv));
        current += PrintRightAVXOperand(current);
        AppendToBuffer(",0x%x", *current++);
        break;
      case 0x0E:
        AppendToBuffer("vpblendw %s,%s,", NameOfAVXRegister(regop),
                       NameOfAVXRegister(vvvv));
        current += PrintRightAVXOperand(current);
        AppendToBuffer(",0x%x", *current++);
        break;
      case 0x0F:
        AppendToBuffer("vpalignr %s,%s,", NameOfAVXRegister(regop),
                       NameOfAVXRegister(vvvv));
        current += PrintRightAVXOperand(current);
        AppendToBuffer(",0x%x", *current++);
        break;
      case 0x14:
        AppendToBuffer("vpextrb ");
        current += PrintRightByteOperand(current);
        AppendToBuffer(",%s,0x%x", NameOfAVXRegister(regop), *current++);
        break;
      case 0x15:
        AppendToBuffer("vpextrw ");
        current += PrintRightOperand(current);
        AppendToBuffer(",%s,0x%x", NameOfAVXRegister(regop), *current++);
        break;
      case 0x16:
        AppendToBuffer("vpextr%c ", rex_w() ? 'q' : 'd');
        current += PrintRightOperand(current);
        AppendToBuffer(",%s,0x%x", NameOfAVXRegister(regop), *current++);
        break;
      case 0x17:
        AppendToBuffer("vextractps ");
        current += PrintRightOperand(current);
        AppendToBuffer(",%s,0x%x", NameOfAVXRegister(regop), *current++);
        break;
      case 0x19:
        AppendToBuffer("vextractf128 ");
        current += PrintRightXMMOperand(current);
        AppendToBuffer(",%s,0x%x", NameOfAVXRegister(regop), *current++);
        break;
      case 0x1D:
        AppendToBuffer("vcvtps2ph ");
        current += PrintRightXMMOperand(current);
        AppendToBuffer(",%s,0x%x", NameOfAVXRegister(regop), *current++);
        break;
      case 0x20:
        AppendToBuffer("vpinsrb %s,%s,", NameOfAVXRegister(regop),
                       NameOfAVXRegister(vvvv));
        current += PrintRightByteOperand(current);
        AppendToBuffer(",0x%x", *current++);
        break;
      case 0x21:
        AppendToBuffer("vinsertps %s,%s,", NameOfAVXRegister(regop),
                       NameOfAVXRegister(vvvv));
        current += PrintRightAVXOperand(current);
        AppendToBuffer(",0x%x", *current++);
        break;
      case 0x22:
        AppendToBuffer("vpinsr%c %s,%s,", rex_w() ? 'q' : 'd',
                       NameOfAVXRegister(regop), NameOfAVXRegister(vvvv));
        current += PrintRightOperand(current);
        AppendToBuffer(",0x%x", *current++);
        break;
      case 0x38:
        AppendToBuffer("vinserti128 %s,%s,", NameOfAVXRegister(regop),
                       NameOfAVXRegister(vvvv));
        current += PrintRightXMMOperand(current);
        AppendToBuffer(",0x%x", *current++);
        break;
      case 0x4A: {
        AppendToBuffer("vblendvps %s,%s,", NameOfAVXRegister(regop),
                       NameOfAVXRegister(vvvv));
        current += PrintRightAVXOperand(current);
        AppendToBuffer(",%s", NameOfAVXRegister((*current++) >> 4));
        break;
      }
      case 0x4B: {
        AppendToBuffer("vblendvpd %s,%s,", NameOfAVXRegister(regop),
                       NameOfAVXRegister(vvvv));
        current += PrintRightAVXOperand(current);
        AppendToBuffer(",%s", NameOfAVXRegister((*current++) >> 4));
        break;
      }
      case 0x4C: {
        AppendToBuffer("vpblendvb %s,%s,", NameOfAVXRegister(regop),
                       NameOfAVXRegister(vvvv));
        current += PrintRightAVXOperand(current);
        AppendToBuffer(",%s", NameOfAVXRegister((*current++) >> 4));
        break;
      }
      default:
        UnimplementedInstruction();
    }
  } else if (vex_f3() && vex_0f()) {
    int mod, regop, rm, vvvv = vex_vreg();
    get_modrm(*current, &mod, &regop, &rm);
    switch (opcode) {
      case 0x10:
        AppendToBuffer("vmovss %s,", NameOfAVXRegister(regop));
        if (mod == 3) {
          AppendToBuffer("%s,", NameOfAVXRegister(vvvv));
        }
        current += PrintRightAVXOperand(current);
        break;
      case 0x11:
        AppendToBuffer("vmovss ");
        current += PrintRightAVXOperand(current);
        if (mod == 3) {
          AppendToBuffer(",%s", NameOfAVXRegister(vvvv));
        }
        AppendToBuffer(",%s", NameOfAVXRegister(regop));
        break;
      case 0x16:
        AppendToBuffer("vmovshdup %s,", NameOfAVXRegister(regop));
        current += PrintRightAVXOperand(current);
        break;
      case 0x2A:
        AppendToBuffer("%s %s,%s,", vex_w() ? "vcvtqsi2ss" : "vcvtlsi2ss",
                       NameOfAVXRegister(regop), NameOfAVXRegister(vvvv));
        current += PrintRightOperand(current);
        break;
      case 0x2C:
        AppendToBuffer("vcvttss2si%s %s,", vex_w() ? "q" : "",
                       NameOfCPURegister(regop));
        current += PrintRightAVXOperand(current);
        break;
      case 0x51:
        AppendToBuffer("vsqrtss %s,%s,", NameOfAVXRegister(regop),
                       NameOfAVXRegister(vvvv));
        current += PrintRightAVXOperand(current);
        break;
      case 0x58:
        AppendToBuffer("vaddss %s,%s,", NameOfAVXRegister(regop),
                       NameOfAVXRegister(vvvv));
        current += PrintRightAVXOperand(current);
        break;
      case 0x59:
        AppendToBuffer("vmulss %s,%s,", NameOfAVXRegister(regop),
                       NameOfAVXRegister(vvvv));
        current += PrintRightAVXOperand(current);
        break;
      case 0x5A:
        AppendToBuffer("vcvtss2sd %s,%s,", NameOfAVXRegister(regop),
                       NameOfAVXRegister(vvvv));
        current += PrintRightAVXOperand(current);
        break;
      case 0x5B:
        AppendToBuffer("vcvttps2dq %s,", NameOfAVXRegister(regop));
        current += PrintRightAVXOperand(current);
        break;
      case 0x5C:
        AppendToBuffer("vsubss %s,%s,", NameOfAVXRegister(regop),
                       NameOfAVXRegister(vvvv));
        current += PrintRightAVXOperand(current);
        break;
      case 0x5D:
        AppendToBuffer("vminss %s,%s,", NameOfAVXRegister(regop),
                       NameOfAVXRegister(vvvv));
        current += PrintRightAVXOperand(current);
        break;
      case 0x5E:
        AppendToBuffer("vdivss %s,%s,", NameOfAVXRegister(regop),
                       NameOfAVXRegister(vvvv));
        current += PrintRightAVXOperand(current);
        break;
      case 0x5F:
        AppendToBuffer("vmaxss %s,%s,", NameOfAVXRegister(regop),
                       NameOfAVXRegister(vvvv));
        current += PrintRightAVXOperand(current);
        break;
      case 0x6F:
        AppendToBuffer("vmovdqu %s,", NameOfAVXRegister(regop));
        current += PrintRightAVXOperand(current);
        break;
      case 0x70:
        AppendToBuffer("vpshufhw %s,", NameOfAVXRegister(regop));
        current += PrintRightAVXOperand(current);
        AppendToBuffer(",0x%x", *current++);
        break;
      case 0x7F:
        AppendToBuffer("vmovdqu ");
        current += PrintRightAVXOperand(current);
        AppendToBuffer(",%s", NameOfAVXRegister(regop));
        break;
      case 0xE6:
        AppendToBuffer("vcvtdq2pd %s,", NameOfAVXRegister(regop));
        current += PrintRightXMMOperand(current);
        break;
      case 0xC2:
        AppendToBuffer("vcmpss %s,%s,", NameOfAVXRegister(regop),
                       NameOfAVXRegister(vvvv));
        current += PrintRightAVXOperand(current);
        AppendToBuffer(", (%s)", cmp_pseudo_op[*current]);
        current += 1;
        break;
      default:
        UnimplementedInstruction();
    }
  } else if (vex_f2() && vex_0f()) {
    int mod, regop, rm, vvvv = vex_vreg();
    get_modrm(*current, &mod, &regop, &rm);
    switch (opcode) {
      case 0x10:
        AppendToBuffer("vmovsd %s,", NameOfAVXRegister(regop));
        if (mod == 3) {
          AppendToBuffer("%s,", NameOfAVXRegister(vvvv));
        }
        current += PrintRightAVXOperand(current);
        break;
      case 0x11:
        AppendToBuffer("vmovsd ");
        current += PrintRightAVXOperand(current);
        if (mod == 3) {
          AppendToBuffer(",%s", NameOfAVXRegister(vvvv));
        }
        AppendToBuffer(",%s", NameOfAVXRegister(regop));
        break;
      case 0x12:
        AppendToBuffer("vmovddup %s,", NameOfAVXRegister(regop));
        current += PrintRightAVXOperand(current);
        break;
      case 0x2A:
        AppendToBuffer("%s %s,%s,", vex_w() ? "vcvtqsi2sd" : "vcvtlsi2sd",
                       NameOfAVXRegister(regop), NameOfAVXRegister(vvvv));
        current += PrintRightOperand(current);
        break;
      case 0x2C:
        AppendToBuffer("vcvttsd2si%s %s,", vex_w() ? "q" : "",
                       NameOfCPURegister(regop));
        current += PrintRightAVXOperand(current);
        break;
      case 0x2D:
        AppendToBuffer("vcvtsd2si%s %s,", vex_w() ? "q" : "",
                       NameOfCPURegister(regop));
        current += PrintRightAVXOperand(current);
        break;
      case 0xF0:
        AppendToBuffer("vlddqu %s,", NameOfAVXRegister(regop));
        current += PrintRightAVXOperand(current);
        break;
      case 0x70:
        AppendToBuffer("vpshuflw %s,", NameOfAVXRegister(regop));
        current += PrintRightAVXOperand(current);
        AppendToBuffer(",0x%x", *current++);
        break;
      case 0x7C:
        AppendToBuffer("vhaddps %s,%s,", NameOfAVXRegister(regop),
                       NameOfAVXRegister(vvvv));
        current += PrintRightAVXOperand(current);
        break;
      case 0xC2:
        AppendToBuffer("vcmpsd %s,%s,", NameOfAVXRegister(regop),
                       NameOfAVXRegister(vvvv));
        current += PrintRightAVXOperand(current);
        AppendToBuffer(", (%s)", cmp_pseudo_op[*current]);
        current += 1;
        break;
#define DISASM_SSE2_INSTRUCTION_LIST_SD(instruction, _1, _2, opcode)     \
  case 0x##opcode:                                                       \
    AppendToBuffer("v" #instruction " %s,%s,", NameOfAVXRegister(regop), \
                   NameOfAVXRegister(vvvv));                             \
    current += PrintRightAVXOperand(current);                            \
    break;
        SSE2_INSTRUCTION_LIST_SD(DISASM_SSE2_INSTRUCTION_LIST_SD)
#undef DISASM_SSE2_INSTRUCTION_LIST_SD
      default:
        UnimplementedInstruction();
    }
  } else if (vex_none() && vex_0f38()) {
    int mod, regop, rm, vvvv = vex_vreg();
    get_modrm(*current, &mod, &regop, &rm);
    const char* mnem = "?";
    switch (opcode) {
      case 0xF2:
        AppendToBuffer("andn%c %s,%s,", operand_size_code(),
                       NameOfCPURegister(regop), NameOfCPURegister(vvvv));
        current += PrintRightOperand(current);
        break;
      case 0xF5:
        AppendToBuffer("bzhi%c %s,", operand_size_code(),
                       NameOfCPURegister(regop));
        current += PrintRightOperand(current);
        AppendToBuffer(",%s", NameOfCPURegister(vvvv));
        break;
      case 0xF7:
        AppendToBuffer("bextr%c %s,", operand_size_code(),
                       NameOfCPURegister(regop));
        current += PrintRightOperand(current);
        AppendToBuffer(",%s", NameOfCPURegister(vvvv));
        break;
      case 0xF3:
        switch (regop) {
          case 1:
            mnem = "blsr";
            break;
          case 2:
            mnem = "blsmsk";
            break;
          case 3:
            mnem = "blsi";
            break;
          default:
            UnimplementedInstruction();
        }
        AppendToBuffer("%s%c %s,", mnem, operand_size_code(),
                       NameOfCPURegister(vvvv));
        current += PrintRightOperand(current);
        mnem = "?";
        break;
      default:
        UnimplementedInstruction();
    }
  } else if (vex_f2() && vex_0f38()) {
    int mod, regop, rm, vvvv = vex_vreg();
    get_modrm(*current, &mod, &regop, &rm);
    switch (opcode) {
      case 0xF5:
        AppendToBuffer("pdep%c %s,%s,", operand_size_code(),
                       NameOfCPURegister(regop), NameOfCPURegister(vvvv));
        current += PrintRightOperand(current);
        break;
      case 0xF6:
        AppendToBuffer("mulx%c %s,%s,", operand_size_code(),
                       NameOfCPURegister(regop), NameOfCPURegister(vvvv));
        current += PrintRightOperand(current);
        break;
      case 0xF7:
        AppendToBuffer("shrx%c %s,", operand_size_code(),
                       NameOfCPURegister(regop));
        current += PrintRightOperand(current);
        AppendToBuffer(",%s", NameOfCPURegister(vvvv));
        break;
      case 0x50:
        AppendToBuffer("vpdpbssd %s,%s,", NameOfAVXRegister(regop),
                       NameOfAVXRegister(vvvv));
        current += PrintRightAVXOperand(current);
        break;
      default:
        UnimplementedInstruction();
    }
  } else if (vex_f3() && vex_0f38()) {
    int mod, regop, rm, vvvv = vex_vreg();
    get_modrm(*current, &mod, &regop, &rm);
    switch (opcode) {
      case 0xF5:
        AppendToBuffer("pext%c %s,%s,", operand_size_code(),
                       NameOfCPURegister(regop), NameOfCPURegister(vvvv));
        current += PrintRightOperand(current);
        break;
      case 0xF7:
        AppendToBuffer("sarx%c %s,", operand_size_code(),
                       NameOfCPURegister(regop));
        current += PrintRightOperand(current);
        AppendToBuffer(",%s", NameOfCPURegister(vvvv));
        break;
      default:
        UnimplementedInstruction();
    }
  } else if (vex_f2() && vex_0f3a()) {
    int mod, regop, rm;
    get_modrm(*current, &mod, &regop, &rm);
    switch (opcode) {
      case 0xF0:
        AppendToBuffer("rorx%c %s,", operand_size_code(),
                       NameOfCPURegister(regop));
        current += PrintRightOperand(current);
        switch (operand_size()) {
          case OPERAND_DOUBLEWORD_SIZE:
            AppendToBuffer(",%d", *current & 0x1F);
            break;
          case OPERAND_QUADWORD_SIZE:
            AppendToBuffer(",%d", *current & 0x3F);
            break;
          default:
            UnimplementedInstruction();
        }
        current += 1;
        break;
      default:
        UnimplementedInstruction();
    }
  } else if (vex_none() && vex_0f()) {
    int mod, regop, rm, vvvv = vex_vreg();
    get_modrm(*current, &mod, &regop, &rm);
    switch (opcode) {
      case 0x10:
        AppendToBuffer("vmovups %s,", NameOfAVXRegister(regop));
        current += PrintRightAVXOperand(current);
        break;
      case 0x11:
        AppendToBuffer("vmovups ");
        current += PrintRightAVXOperand(current);
        AppendToBuffer(",%s", NameOfAVXRegister(regop));
        break;
      case 0x12:
        if (mod == 0b11) {
          AppendToBuffer("vmovhlps %s,%s,", NameOfAVXRegister(regop),
                         NameOfAVXRegister(vvvv));
          current += PrintRightAVXOperand(current);
        } else {
          AppendToBuffer("vmovlps %s,%s,", NameOfAVXRegister(regop),
                         NameOfAVXRegister(vvvv));
          current += PrintRightAVXOperand(current);
        }
        break;
      case 0x13:
        AppendToBuffer("vmovlps ");
        current += PrintRightAVXOperand(current);
        AppendToBuffer(",%s", NameOfAVXRegister(regop));
        break;
      case 0x16:
        if (mod == 0b11) {
          AppendToBuffer("vmovlhps %s,%s,", NameOfAVXRegister(regop),
                         NameOfAVXRegister(vvvv));
          current += PrintRightAVXOperand(current);
        } else {
          AppendToBuffer("vmovhps %s,%s,", NameOfAVXRegister(regop),
                         NameOfAVXRegister(vvvv));
          current += PrintRightAVXOperand(current);
        }
        break;
      case 0x17:
        AppendToBuffer("vmovhps ");
        current += PrintRightAVXOperand(current);
        AppendToBuffer(",%s", NameOfAVXRegister(regop));
        break;
      case 0x28:
        AppendToBuffer("vmovaps %s,", NameOfAVXRegister(regop));
        current += PrintRightAVXOperand(current);
        break;
      case 0x29:
        AppendToBuffer("vmovaps ");
        current += PrintRightAVXOperand(current);
        AppendToBuffer(",%s", NameOfAVXRegister(regop));
        break;
      case 0x2E:
        AppendToBuffer("vucomiss %s,", NameOfAVXRegister(regop));
        current += PrintRightAVXOperand(current);
        break;
      case 0x50:
        AppendToBuffer("vmovmskps %s,", NameOfCPURegister(regop));
        current += PrintRightAVXOperand(current);
        break;
      case 0xC2: {
        AppendToBuffer("vcmpps %s,%s,", NameOfAVXRegister(regop),
                       NameOfAVXRegister(vvvv));
        current += PrintRightAVXOperand(current);
        AppendToBuffer(", (%s)", cmp_pseudo_op[*current]);
        current += 1;
        break;
      }
      case 0xC6: {
        AppendToBuffer("vshufps %s,%s,", NameOfAVXRegister(regop),
                       NameOfAVXRegister(vvvv));
        current += PrintRightAVXOperand(current);
        AppendToBuffer(",0x%x", *current++);
        break;
      }
#define SSE_UNOP_CASE(instruction, unused, code)                       \
  case 0x##code:                                                       \
    AppendToBuffer("v" #instruction " %s,", NameOfAVXRegister(regop)); \
    current += PrintRightAVXOperand(current);                          \
    break;
        SSE_UNOP_INSTRUCTION_LIST(SSE_UNOP_CASE)
#undef SSE_UNOP_CASE
#define SSE_BINOP_CASE(instruction, unused, code)                        \
  case 0x##code:                                                         \
    AppendToBuffer("v" #instruction " %s,%s,", NameOfAVXRegister(regop), \
                   NameOfAVXRegister(vvvv));                             \
    current += PrintRightAVXOperand(current);                            \
    break;
        SSE_BINOP_INSTRUCTION_LIST(SSE_BINOP_CASE)
#undef SSE_BINOP_CASE
      default:
        UnimplementedInstruction();
    }
  } else if (vex_66() && vex_0f()) {
    int mod, regop, rm, vvvv = vex_vreg();
    get_modrm(*current, &mod, &regop, &rm);
    switch (opcode) {
      case 0x10:
        AppendToBuffer("vmovupd %s,", NameOfAVXRegister(regop));
        current += PrintRightAVXOperand(current);
        break;
      case 0x11:
        AppendToBuffer("vmovupd ");
        current += PrintRightAVXOperand(current);
        AppendToBuffer(",%s", NameOfAVXRegister(regop));
        break;
      case 0x28:
        AppendToBuffer("vmovapd %s,", NameOfAVXRegister(regop));
        current += PrintRightAVXOperand(current);
        break;
      case 0x29:
        AppendToBuffer("vmovapd ");
        current += PrintRightAVXOperand(current);
        AppendToBuffer(",%s", NameOfAVXRegister(regop));
        break;
      case 0x50:
        AppendToBuffer("vmovmskpd %s,", NameOfCPURegister(regop));
        current += PrintRightAVXOperand(current);
        break;
      case 0x6E:
        AppendToBuffer("vmov%c %s,", vex_w() ? 'q' : 'd',
                       NameOfAVXRegister(regop));
        current += PrintRightOperand(current);
        break;
      case 0x6F:
        AppendToBuffer("vmovdqa %s,", NameOfAVXRegister(regop));
        current += PrintRightAVXOperand(current);
        break;
      case 0x70:
        AppendToBuffer("vpshufd %s,", NameOfAVXRegister(regop));
        current += PrintRightAVXOperand(current);
        AppendToBuffer(",0x%x", *current++);
        break;
      case 0x71:
        AppendToBuffer("vps%sw %s,", sf_str[regop / 2],
                       NameOfAVXRegister(vvvv));
        current += PrintRightAVXOperand(current);
        AppendToBuffer(",%u", *current++);
        break;
      case 0x72:
        AppendToBuffer("vps%sd %s,", sf_str[regop / 2],
                       NameOfAVXRegister(vvvv));
        current += PrintRightAVXOperand(current);
        AppendToBuffer(",%u", *current++);
        break;
      case 0x73:
        AppendToBuffer("vps%sq %s,", sf_str[regop / 2],
                       NameOfAVXRegister(vvvv));
        current += PrintRightAVXOperand(current);
        AppendToBuffer(",%u", *current++);
        break;
      case 0x7E:
        AppendToBuffer("vmov%c ", vex_w() ? 'q' : 'd');
        current += PrintRightOperand(current);
        AppendToBuffer(",%s", NameOfAVXRegister(regop));
        break;
      case 0xC2: {
        AppendToBuffer("vcmppd %s,%s,", NameOfAVXRegister(regop),
                       NameOfAVXRegister(vvvv));
        current += PrintRightAVXOperand(current);
        AppendToBuffer(", (%s)", cmp_pseudo_op[*current]);
        current += 1;
        break;
      }
      case 0xC4:
        AppendToBuffer("vpinsrw %s,%s,", NameOfAVXRegister(regop),
                       NameOfAVXRegister(vvvv));
        current += PrintRightOperand(current);
        AppendToBuffer(",0x%x", *current++);
        break;
      case 0xC5:
        AppendToBuffer("vpextrw %s,", NameOfCPURegister(regop));
        current += PrintRightAVXOperand(current);
        AppendToBuffer(",0x%x", *current++);
        break;
      case 0xD7:
        AppendToBuffer("vpmovmskb %s,", NameOfCPURegister(regop));
        current += PrintRightAVXOperand(current);
        break;
#define DECLARE_SSE_AVX_DIS_CASE(instruction, notUsed1, notUsed2, opcode) \
  case 0x##opcode: {                                                      \
    AppendToBuffer("v" #instruction " %s,%s,", NameOfAVXRegister(regop),  \
                   NameOfAVXRegister(vvvv));                              \
    current += PrintRightAVXOperand(current);                             \
    break;                                                                \
  }

        SSE2_INSTRUCTION_LIST(DECLARE_SSE_AVX_DIS_CASE)
#undef DECLARE_SSE_AVX_DIS_CASE
#define DECLARE_SSE_UNOP_AVX_DIS_CASE(instruction, opcode, SIMDRegister)  \
  case 0x##opcode: {                                                      \
    AppendToBuffer("v" #instruction " %s,", NameOf##SIMDRegister(regop)); \
    current += PrintRightAVXOperand(current);                             \
    break;                                                                \
  }
        DECLARE_SSE_UNOP_AVX_DIS_CASE(ucomisd, 2E, AVXRegister)
        DECLARE_SSE_UNOP_AVX_DIS_CASE(sqrtpd, 51, AVXRegister)
        DECLARE_SSE_UNOP_AVX_DIS_CASE(cvtpd2ps, 5A, XMMRegister)
        DECLARE_SSE_UNOP_AVX_DIS_CASE(cvtps2dq, 5B, AVXRegister)
        DECLARE_SSE_UNOP_AVX_DIS_CASE(cvttpd2dq, E6, XMMRegister)
#undef DECLARE_SSE_UNOP_AVX_DIS_CASE
      default:
        UnimplementedInstruction();
    }

  } else {
    UnimplementedInstruction();
  }

  return static_cast<int>(current - data);
}

// Returns number of bytes used, including *data.
int DisassemblerX64::FPUInstruction(uint8_t* data) {
  uint8_t escape_opcode = *data;
  DCHECK_EQ(0xD8, escape_opcode & 0xF8);
  uint8_t modrm_byte = *(data + 1);

  if (modrm_byte >= 0xC0) {
    return RegisterFPUInstruction(escape_opcode, modrm_byte);
  } else {
    return MemoryFPUInstruction(escape_opcode, modrm_byte, data + 1);
  }
}

int DisassemblerX64::MemoryFPUInstruction(int escape_opcode, int modrm_byte,
                                          uint8_t* modrm_start) {
  const char* mnem = "?";
  int regop = (modrm_byte >> 3) & 0x7;  // reg/op field of modrm byte.
  switch (escape_opcode) {
    case 0xD9:
      switch (regop) {
        case 0:
          mnem = "fld_s";
          break;
        case 3:
          mnem = "fstp_s";
          break;
        case 7:
          mnem = "fstcw";
          break;
        default:
          UnimplementedInstruction();
      }
      break;

    case 0xDB:
      switch (regop) {
        case 0:
          mnem = "fild_s";
          break;
        case 1:
          mnem = "fisttp_s";
          break;
        case 2:
          mnem = "fist_s";
          break;
        case 3:
          mnem = "fistp_s";
          break;
        default:
          UnimplementedInstruction();
      }
      break;

    case 0xDD:
      switch (regop) {
        case 0:
          mnem = "fld_d";
          break;
        case 3:
          mnem = "fstp_d";
          break;
        default:
          UnimplementedInstruction();
      }
      break;

    case 0xDF:
      switch (regop) {
        case 5:
          mnem = "fild_d";
          break;
        case 7:
          mnem = "fistp_d";
          break;
        default:
          UnimplementedInstruction();
      }
      break;

    default:
      UnimplementedInstruction();
  }
  AppendToBuffer("%s ", mnem);
  int count = PrintRightOperand(modrm_start);
  return count + 1;
}

int DisassemblerX64::RegisterFPUInstruction(int escape_opcode,
                                            uint8_t modrm_byte) {
  bool has_register = false;  // Is the FPU register encoded in modrm_byte?
  const char* mnem = "?";

  switch (escape_opcode) {
    case 0xD8:
      UnimplementedInstruction();
      break;

    case 0xD9:
      switch (modrm_byte & 0xF8) {
        case 0xC0:
          mnem = "fld";
          has_register = true;
          break;
        case 0xC8:
          mnem = "fxch";
          has_register = true;
          break;
        default:
          switch (modrm_byte) {
            case 0xE0:
              mnem = "fchs";
              break;
            case 0xE1:
              mnem = "fabs";
              break;
            case 0xE3:
              mnem = "fninit";
              break;
            case 0xE4:
              mnem = "ftst";
              break;
            case 0xE8:
              mnem = "fld1";
              break;
            case 0xEB:
              mnem = "fldpi";
              break;
            case 0xED:
              mnem = "fldln2";
              break;
            case 0xEE:
              mnem = "fldz";
              break;
            case 0xF0:
              mnem = "f2xm1";
              break;
            case 0xF1:
              mnem = "fyl2x";
              break;
            case 0xF2:
              mnem = "fptan";
              break;
            case 0xF5:
              mnem = "fprem1";
              break;
            case 0xF7:
              mnem = "fincstp";
              break;
            case 0xF8:
              mnem = "fprem";
              break;
            case 0xFC:
              mnem = "frndint";
              break;
            case 0xFD:
              mnem = "fscale";
              break;
            case 0xFE:
              mnem = "fsin";
              break;
            case 0xFF:
              mnem = "fcos";
              break;
            default:
              UnimplementedInstruction();
          }
      }
      break;

    case 0xDA:
      if (modrm_byte == 0xE9) {
        mnem = "fucompp";
      } else {
        UnimplementedInstruction();
      }
      break;

    case 0xDB:
      if ((modrm_byte & 0xF8) == 0xE8) {
        mnem = "fucomi";
        has_register = true;
      } else if (modrm_byte == 0xE2) {
        mnem = "fclex";
      } else if (modrm_byte == 0xE3) {
        mnem = "fninit";
      } else {
        UnimplementedInstruction();
      }
      break;

    case 0xDC:
      has_register = true;
      switch (modrm_byte & 0xF8) {
        case 0xC0:
          mnem = "fadd";
          break;
        case 0xE8:
          mnem = "fsub";
          break;
        case 0xC8:
          mnem = "fmul";
          break;
        case 0xF8:
          mnem = "fdiv";
          break;
        default:
          UnimplementedInstruction();
      }
      break;

    case 0xDD:
      has_register = true;
      switch (modrm_byte & 0xF8) {
        case 0xC0:
          mnem = "ffree";
          break;
        case 0xD8:
          mnem = "fstp";
          break;
        default:
          UnimplementedInstruction();
      }
      break;

    case 0xDE:
      if (modrm_byte == 0xD9) {
        mnem = "fcompp";
      } else {
        has_register = true;
        switch (modrm_byte & 0xF8) {
          case 0xC0:
            mnem = "faddp";
            break;
          case 0xE8:
            mnem = "fsubp";
            break;
          case 0xC8:
            mnem = "fmulp";
            break;
          case 0xF8:
            mnem = "fdivp";
            break;
          default:
            UnimplementedInstruction();
        }
      }
      break;

    case 0xDF:
      if (modrm_byte == 0xE0) {
        mnem = "fnstsw_ax";
      } else if ((modrm_byte & 0xF8) == 0xE8) {
        mnem = "fucomip";
        has_register = true;
      }
      break;

    default:
      UnimplementedInstruction();
  }

  if (has_register) {
    AppendToBuffer("%s st%d", mnem, modrm_byte & 0x7);
  } else {
    AppendToBuffer("%s", mnem);
  }
  return 2;
}

// Handle all two-byte opcodes, which start with 0x0F.
// These instructions may be affected by an 0x66, 0xF2, or 0xF3 prefix.
int DisassemblerX64::TwoByteOpcodeInstruction(uint8_t* data) {
  uint8_t opcode = *(data + 1);
  uint8_t* current = data + 2;
  // At return, "current" points to the start of the next instruction.
  const char* mnemonic = TwoByteMnemonic(opcode);
  // Not every instruction will use this, but it doesn't hurt to figure it out
  // here, since it doesn't update any pointers.
  int mod, regop, rm;
  get_modrm(*current, &mod, &regop, &rm);
  if (operand_size_ == 0x66) {
    // These are three-byte opcodes, see ThreeByteOpcodeInstruction.
    DCHECK_NE(0x38, opcode);
    DCHECK_NE(0x3A, opcode);
    // 0x66 0x0F prefix.
    if (opcode == 0xC1) {
      current += PrintOperands("xadd", OPER_REG_OP_ORDER, current);
    } else if (opcode == 0x1F) {
      current++;
      if (rm == 4) {  // SIB byte present.
        current++;
      }
      if (mod == 1) {  // Byte displacement.
        current += 1;
      } else if (mod == 2) {  // 32-bit displacement.
        current += 4;
      }  // else no immediate displacement.
      AppendToBuffer("nop");
    } else if (opcode == 0x10) {
      current += PrintOperands("movupd", XMMREG_XMMOPER_OP_ORDER, current);
    } else if (opcode == 0x11) {
      current += PrintOperands("movupd", XMMOPER_XMMREG_OP_ORDER, current);
    } else if (opcode == 0x28) {
      current += PrintOperands("movapd", XMMREG_XMMOPER_OP_ORDER, current);
    } else if (opcode == 0x29) {
      current += PrintOperands("movapd", XMMOPER_XMMREG_OP_ORDER, current);
    } else if (opcode == 0x6E) {
      current += PrintOperands(rex_w() ? "movq" : "movd", XMMREG_OPER_OP_ORDER,
                               current);
    } else if (opcode == 0x6F) {
      current += PrintOperands("movdqa", XMMREG_XMMOPER_OP_ORDER, current);
    } else if (opcode == 0x7E) {
      current += PrintOperands(rex_w() ? "movq" : "movd", OPER_XMMREG_OP_ORDER,
                               current);
    } else if (opcode == 0x7F) {
      current += PrintOperands("movdqa", XMMOPER_XMMREG_OP_ORDER, current);
    } else if (opcode == 0xD6) {
      current += PrintOperands("movq", XMMOPER_XMMREG_OP_ORDER, current);
    } else if (opcode == 0x50) {
      App
```