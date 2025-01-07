Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/diagnostics/ia32/disasm-ia32.cc`.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core purpose:** The filename `disasm-ia32.cc` strongly suggests this code is a disassembler for the IA32 (x86) architecture within the V8 JavaScript engine. The initial comments confirm this.

2. **Analyze the key data structures:**
    * `ByteMnemonic`:  This structure clearly maps byte opcodes to their mnemonic names and operand order. There are several arrays of these structures (`two_operands_instr`, `zero_operands_instr`, etc.), each representing a group of instructions with similar operand characteristics.
    * `InstructionDesc`: This structure holds the mnemonic, instruction type, and operand order for a given opcode.
    * `InstructionTable`: This class appears to be a lookup table that maps a byte opcode to its `InstructionDesc`. The `Init()` method populates this table by iterating through the `ByteMnemonic` arrays.

3. **Understand the `DisassemblerIA32` class:** This is the main class responsible for the disassembling process.
    * The constructor takes a `NameConverter` (likely for formatting register names and addresses) and an `UnimplementedOpcodeAction`.
    * The `InstructionDecode` method is the core function. It takes a buffer and an instruction pointer and attempts to decode the instruction. However, the provided snippet *only* shows the declaration, not the implementation.
    * The private methods (e.g., `PrintRightOperand`, `PrintOperands`, `JumpConditional`) are helper functions used within `InstructionDecode` to handle different instruction formats. They are responsible for formatting the output string.

4. **Address the specific questions:**
    * **Functionality:**  Based on the analysis, the primary function is to take raw IA32 machine code as input (a sequence of bytes) and translate it into a human-readable assembly language representation.
    * **`.tq` extension:** The code has a `.cc` extension, indicating it's a C++ source file, not a Torque file.
    * **Relationship to JavaScript:**  As part of the V8 engine, this disassembler is used for debugging and introspection of the generated machine code for JavaScript execution. It doesn't directly execute JavaScript but helps in understanding how JavaScript is compiled and run. The example of debugging helps illustrate this.
    * **Code Logic Inference:**  While the full `InstructionDecode` isn't shown, the logic within the helper functions is clear: identify the opcode, determine the operands based on ModR/M and SIB bytes, and format the output string. The example demonstrates a simple "add" instruction.
    * **Common Programming Errors:** The disassembler works at a lower level than typical user code, so common user errors aren't directly applicable. However, it could expose issues in compiler code generation or JIT compilation. An example of an incorrect JIT compiler output being revealed by the disassembler is relevant.
    * **Summary of Functionality (Part 1):** The code in this part focuses on the *data structures and initialization* needed for disassembling IA32 instructions. It sets up tables to map opcodes to mnemonics and defines the core `DisassemblerIA32` class. The actual decoding logic will likely be in subsequent parts.

5. **Structure the answer:** Organize the findings into clear sections that address each of the user's questions. Use bullet points and code examples to enhance readability.

6. **Refine and review:** Ensure the language is precise and avoids jargon where possible. Double-check the code examples and explanations for accuracy. For instance, initially, I might have focused too much on the *details* of each instruction table. However, the user's request is about overall *functionality*, so a higher-level explanation is more appropriate. Also, make sure to explicitly state that the provided snippet is just a part of the disassembler and not the complete implementation.
这是V8 JavaScript引擎中用于反汇编IA32架构机器码的C++源代码文件。 它的主要功能是将IA32（x86 32位）架构的机器指令字节序列转换成人类可读的汇编语言表示形式。

**以下是它的功能归纳：**

1. **指令识别和助记符查找:** 代码中定义了多个静态的 `ByteMnemonic` 结构体数组（例如 `two_operands_instr`, `zero_operands_instr` 等）。这些数组将 IA32 指令的字节码与对应的汇编助记符（例如 "add", "mov", "jmp"）以及操作数顺序关联起来。`InstructionTable` 类则负责构建一个查找表，通过指令的第一个字节快速找到对应的助记符和指令类型。

2. **操作数解析和格式化:**  `DisassemblerIA32` 类包含了多个方法来解析和格式化指令的操作数。
    * `get_modrm` 和 `get_sib` 用于解析 ModR/M 和 SIB 字节，这些字节用于确定指令的操作数是寄存器、直接寻址还是间接寻址。
    * `PrintRightOperandHelper`, `PrintRightOperand`, `PrintRightByteOperand`, `PrintRightXMMOperand` 等方法负责根据不同的寻址模式和操作数类型，将操作数格式化为字符串（例如寄存器名、内存地址）。
    * `PrintOperands` 方法将助记符和格式化后的操作数组合成完整的汇编指令字符串。

3. **处理不同指令类型:** 代码针对不同类型的 IA32 指令有特定的处理逻辑，例如：
    * **双操作数指令:**  通过 `two_operands_instr` 表处理。
    * **零操作数指令:** 通过 `zero_operands_instr` 表处理。
    * **调用和跳转指令:** 通过 `call_jump_instr` 表处理。
    * **立即数指令:** 通过 `short_immediate_instr` 和 `byte_immediate_instr` 表处理，并处理立即数的格式化。
    * **条件跳转指令:**  `JumpConditional` 和 `JumpConditionalShort` 方法处理，并根据条件码查找对应的助记符。
    * **SETcc 和 CMOVcc 指令:** `SetCC` 和 `CMov` 方法处理。
    * **FPU 指令:** `FPUInstruction`, `MemoryFPUInstruction`, `RegisterFPUInstruction` 方法处理浮点运算指令。
    * **AVX 指令:** `AVXInstruction` 方法处理高级向量扩展指令。

4. **VEX 前缀处理:**  代码中包含对 VEX 前缀的处理逻辑 (`vex_byte0_`, `vex_byte1_`, `vex_byte2_`, 以及 `vex_128`, `vex_none`, `vex_66`, `vex_f3`, `vex_f2`, `vex_w`, `vex_0f`, `vex_0f38`, `vex_0f3a`, `vex_vreg`)，这表明该反汇编器能够处理使用 VEX 前缀的指令，这些指令通常用于 AVX 指令集。

5. **输出格式化:** `AppendToBuffer` 方法用于将格式化后的汇编指令片段添加到临时的缓冲区中。 `InstructionDecode` 方法（尽管在这部分代码中没有完整展示）最终会使用这些片段构建完整的反汇编输出。

**关于您提出的问题：**

* **如果 v8/src/diagnostics/ia32/disasm-ia32.cc 以 .tq 结尾，那它是个 v8 torque 源代码:**  提供的代码片段以 `.cc` 结尾，这表明它是 **C++ 源代码**，而不是 Torque 源代码。 Torque 文件通常以 `.tq` 结尾。

* **如果它与 javascript 的功能有关系，请用 javascript 举例说明:**

   该文件本身不包含 JavaScript 代码。它的作用是在 V8 引擎内部，用于调试和分析 V8 生成的机器码。  当 V8 执行 JavaScript 代码时，它会将 JavaScript 代码编译成机器码。这个反汇编器可以用来查看生成的机器码，帮助开发者理解 V8 的编译过程和性能瓶颈。

   **JavaScript 示例（用于触发反汇编 - 需要 V8 内部工具或调试器）:**

   ```javascript
   function add(a, b) {
     return a + b;
   }

   add(5, 10);
   ```

   当 V8 执行 `add(5, 10)` 时，它会将 `add` 函数编译成 IA32 机器码。 使用 V8 的内部工具或调试器（例如 `d8` 的 `--print-code` 选项或 Chrome DevTools 的 Performance 面板），可能会调用到 `disasm-ia32.cc` 中的代码来反汇编 `add` 函数的机器码，从而看到类似以下的汇编输出：

   ```assembly
   mov eax,[esp+0x4]    ; Load argument 'a'
   add eax,[esp+0x8]    ; Add argument 'b'
   ret                  ; Return
   ```

* **如果有代码逻辑推理，请给出假设输入与输出:**

   **假设输入 (机器码字节序列):** `01 03`

   **代码逻辑推理:**

   1. `InstructionTable::Get(0x01)` 会返回 `add` 助记符，`type` 为 `TWO_OPERANDS_INSTR`，`op_order_` 为 `OPER_REG_OP_ORDER`。
   2. `InstructionDecode` (虽然未完整展示) 会识别到 `0x01` 对应 `add` 指令。
   3. 接下来会解析 ModR/M 字节 `03`。
   4. `get_modrm(0x03, &mod, &regop, &rm)` 会得到 `mod = 0`, `regop = 0`, `rm = 3`。
   5. 根据 `OPER_REG_OP_ORDER`，右操作数是内存或寄存器，左操作数是寄存器。
   6. `PrintRightOperand(data)` (假设 `data` 指向 `0x03`) 会根据 `mod` 和 `rm` 解析右操作数，`mod = 0`, `rm = 3` 通常表示 `[ebx]`。
   7. `NameOfCPURegister(regop)` 会返回寄存器名，`regop = 0` 对应 `eax`。
   8. `PrintOperands` 会将它们组合起来。

   **输出 (反汇编结果):** `add [ebx],eax`

* **如果涉及用户常见的编程错误，请举例说明:**

   这个反汇编器本身不直接涉及用户的编程错误。它的作用是分析机器码，而不是执行用户编写的 JavaScript 或 C++ 代码。 然而，它可以帮助诊断一些与代码生成相关的错误。 例如：

   * **错误的 JIT 编译:** 如果 JavaScript 代码在运行时被即时编译（JIT）成错误的机器码，反汇编器可以帮助开发者检查生成的指令是否符合预期，从而定位 JIT 编译器的 bug。
   * **内联失败或优化问题:**  反汇编器可以帮助理解 V8 是否成功内联了某个函数，或者某些优化是否生效。如果生成的机器码不是最优的，可能暗示着优化器存在问题或代码结构不利于优化。

* **这是第1部分，共3部分，请归纳一下它的功能:**

   正如前面总结的，这部分代码主要负责 **IA32 指令的识别和基本的操作数解析框架的建立**。它定义了用于存储指令信息的数据结构 (`ByteMnemonic`, `InstructionDesc`) 和查找表 (`InstructionTable`)，并实现了 `DisassemblerIA32` 类的部分功能，包括操作数格式化的辅助方法和对 VEX 前缀的处理。 核心的指令解码和反汇编流程很可能在后续的部分中实现。  简单来说，**这部分搭建了反汇编 IA32 代码的基础设施**。

Prompt: 
```
这是目录为v8/src/diagnostics/ia32/disasm-ia32.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/diagnostics/ia32/disasm-ia32.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2011 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>

#if V8_TARGET_ARCH_IA32

#include "src/base/compiler-specific.h"
#include "src/base/strings.h"
#include "src/codegen/ia32/fma-instr.h"
#include "src/codegen/ia32/sse-instr.h"
#include "src/diagnostics/disasm.h"

namespace disasm {

enum OperandOrder { UNSET_OP_ORDER = 0, REG_OPER_OP_ORDER, OPER_REG_OP_ORDER };

//------------------------------------------------------------------
// Tables
//------------------------------------------------------------------
struct ByteMnemonic {
  int b;  // -1 terminates, otherwise must be in range (0..255)
  const char* mnem;
  OperandOrder op_order_;
};

static const ByteMnemonic two_operands_instr[] = {
    {0x01, "add", OPER_REG_OP_ORDER},  {0x03, "add", REG_OPER_OP_ORDER},
    {0x09, "or", OPER_REG_OP_ORDER},   {0x0B, "or", REG_OPER_OP_ORDER},
    {0x13, "adc", REG_OPER_OP_ORDER},  {0x1B, "sbb", REG_OPER_OP_ORDER},
    {0x21, "and", OPER_REG_OP_ORDER},  {0x23, "and", REG_OPER_OP_ORDER},
    {0x29, "sub", OPER_REG_OP_ORDER},  {0x2A, "subb", REG_OPER_OP_ORDER},
    {0x2B, "sub", REG_OPER_OP_ORDER},  {0x31, "xor", OPER_REG_OP_ORDER},
    {0x33, "xor", REG_OPER_OP_ORDER},  {0x38, "cmpb", OPER_REG_OP_ORDER},
    {0x39, "cmp", OPER_REG_OP_ORDER},  {0x3A, "cmpb", REG_OPER_OP_ORDER},
    {0x3B, "cmp", REG_OPER_OP_ORDER},  {0x84, "test_b", REG_OPER_OP_ORDER},
    {0x85, "test", REG_OPER_OP_ORDER}, {0x86, "xchg_b", REG_OPER_OP_ORDER},
    {0x87, "xchg", REG_OPER_OP_ORDER}, {0x8A, "mov_b", REG_OPER_OP_ORDER},
    {0x8B, "mov", REG_OPER_OP_ORDER},  {0x8D, "lea", REG_OPER_OP_ORDER},
    {-1, "", UNSET_OP_ORDER}};

static const ByteMnemonic zero_operands_instr[] = {
    {0xC3, "ret", UNSET_OP_ORDER},   {0xC9, "leave", UNSET_OP_ORDER},
    {0x90, "nop", UNSET_OP_ORDER},   {0xF4, "hlt", UNSET_OP_ORDER},
    {0xCC, "int3", UNSET_OP_ORDER},  {0x60, "pushad", UNSET_OP_ORDER},
    {0x61, "popad", UNSET_OP_ORDER}, {0x9C, "pushfd", UNSET_OP_ORDER},
    {0x9D, "popfd", UNSET_OP_ORDER}, {0x9E, "sahf", UNSET_OP_ORDER},
    {0x99, "cdq", UNSET_OP_ORDER},   {0x9B, "fwait", UNSET_OP_ORDER},
    {0xFC, "cld", UNSET_OP_ORDER},   {0xAB, "stos", UNSET_OP_ORDER},
    {-1, "", UNSET_OP_ORDER}};

static const ByteMnemonic call_jump_instr[] = {{0xE8, "call", UNSET_OP_ORDER},
                                               {0xE9, "jmp", UNSET_OP_ORDER},
                                               {-1, "", UNSET_OP_ORDER}};

static const ByteMnemonic short_immediate_instr[] = {
    {0x05, "add", UNSET_OP_ORDER}, {0x0D, "or", UNSET_OP_ORDER},
    {0x15, "adc", UNSET_OP_ORDER}, {0x25, "and", UNSET_OP_ORDER},
    {0x2D, "sub", UNSET_OP_ORDER}, {0x35, "xor", UNSET_OP_ORDER},
    {0x3D, "cmp", UNSET_OP_ORDER}, {-1, "", UNSET_OP_ORDER}};

// Generally we don't want to generate these because they are subject to partial
// register stalls.  They are included for completeness and because the cmp
// variant is used by the RecordWrite stub.  Because it does not update the
// register it is not subject to partial register stalls.
static ByteMnemonic byte_immediate_instr[] = {{0x0C, "or", UNSET_OP_ORDER},
                                              {0x24, "and", UNSET_OP_ORDER},
                                              {0x34, "xor", UNSET_OP_ORDER},
                                              {0x3C, "cmp", UNSET_OP_ORDER},
                                              {-1, "", UNSET_OP_ORDER}};

static const char* const jump_conditional_mnem[] = {
    /*0*/ "jo",  "jno", "jc",  "jnc",
    /*4*/ "jz",  "jnz", "jna", "ja",
    /*8*/ "js",  "jns", "jpe", "jpo",
    /*12*/ "jl", "jnl", "jng", "jg"};

static const char* const set_conditional_mnem[] = {
    /*0*/ "seto",  "setno", "setc",  "setnc",
    /*4*/ "setz",  "setnz", "setna", "seta",
    /*8*/ "sets",  "setns", "setpe", "setpo",
    /*12*/ "setl", "setnl", "setng", "setg"};

static const char* const conditional_move_mnem[] = {
    /*0*/ "cmovo",  "cmovno", "cmovc",  "cmovnc",
    /*4*/ "cmovz",  "cmovnz", "cmovna", "cmova",
    /*8*/ "cmovs",  "cmovns", "cmovpe", "cmovpo",
    /*12*/ "cmovl", "cmovnl", "cmovng", "cmovg"};

static const char* const cmp_pseudo_op[16] = {
    "eq",    "lt",  "le",  "unord", "neq",    "nlt", "nle", "ord",
    "eq_uq", "nge", "ngt", "false", "neq_oq", "ge",  "gt",  "true"};

enum InstructionType {
  NO_INSTR,
  ZERO_OPERANDS_INSTR,
  TWO_OPERANDS_INSTR,
  JUMP_CONDITIONAL_SHORT_INSTR,
  REGISTER_INSTR,
  MOVE_REG_INSTR,
  CALL_JUMP_INSTR,
  SHORT_IMMEDIATE_INSTR,
  BYTE_IMMEDIATE_INSTR
};

struct InstructionDesc {
  const char* mnem;
  InstructionType type;
  OperandOrder op_order_;
};

class InstructionTable {
 public:
  InstructionTable();
  const InstructionDesc& Get(uint8_t x) const { return instructions_[x]; }
  static InstructionTable* get_instance() {
    static InstructionTable table;
    return &table;
  }

 private:
  InstructionDesc instructions_[256];
  void Clear();
  void Init();
  void CopyTable(const ByteMnemonic bm[], InstructionType type);
  void SetTableRange(InstructionType type, uint8_t start, uint8_t end,
                     const char* mnem);
  void AddJumpConditionalShort();
};

InstructionTable::InstructionTable() {
  Clear();
  Init();
}

void InstructionTable::Clear() {
  for (int i = 0; i < 256; i++) {
    instructions_[i].mnem = "";
    instructions_[i].type = NO_INSTR;
    instructions_[i].op_order_ = UNSET_OP_ORDER;
  }
}

void InstructionTable::Init() {
  CopyTable(two_operands_instr, TWO_OPERANDS_INSTR);
  CopyTable(zero_operands_instr, ZERO_OPERANDS_INSTR);
  CopyTable(call_jump_instr, CALL_JUMP_INSTR);
  CopyTable(short_immediate_instr, SHORT_IMMEDIATE_INSTR);
  CopyTable(byte_immediate_instr, BYTE_IMMEDIATE_INSTR);
  AddJumpConditionalShort();
  SetTableRange(REGISTER_INSTR, 0x40, 0x47, "inc");
  SetTableRange(REGISTER_INSTR, 0x48, 0x4F, "dec");
  SetTableRange(REGISTER_INSTR, 0x50, 0x57, "push");
  SetTableRange(REGISTER_INSTR, 0x58, 0x5F, "pop");
  SetTableRange(REGISTER_INSTR, 0x91, 0x97, "xchg eax,");  // 0x90 is nop.
  SetTableRange(MOVE_REG_INSTR, 0xB8, 0xBF, "mov");
}

void InstructionTable::CopyTable(const ByteMnemonic bm[],
                                 InstructionType type) {
  for (int i = 0; bm[i].b >= 0; i++) {
    InstructionDesc* id = &instructions_[bm[i].b];
    id->mnem = bm[i].mnem;
    id->op_order_ = bm[i].op_order_;
    DCHECK_EQ(NO_INSTR, id->type);  // Information not already entered.
    id->type = type;
  }
}

void InstructionTable::SetTableRange(InstructionType type, uint8_t start,
                                     uint8_t end, const char* mnem) {
  for (uint8_t b = start; b <= end; b++) {
    InstructionDesc* id = &instructions_[b];
    DCHECK_EQ(NO_INSTR, id->type);  // Information not already entered.
    id->mnem = mnem;
    id->type = type;
  }
}

void InstructionTable::AddJumpConditionalShort() {
  for (uint8_t b = 0x70; b <= 0x7F; b++) {
    InstructionDesc* id = &instructions_[b];
    DCHECK_EQ(NO_INSTR, id->type);  // Information not already entered.
    id->mnem = jump_conditional_mnem[b & 0x0F];
    id->type = JUMP_CONDITIONAL_SHORT_INSTR;
  }
}

namespace {
int8_t Imm8(const uint8_t* data) {
  return *reinterpret_cast<const int8_t*>(data);
}
uint8_t Imm8_U(const uint8_t* data) {
  return *reinterpret_cast<const uint8_t*>(data);
}
int16_t Imm16(const uint8_t* data) {
  return *reinterpret_cast<const int16_t*>(data);
}
uint16_t Imm16_U(const uint8_t* data) {
  return *reinterpret_cast<const uint16_t*>(data);
}
int32_t Imm32(const uint8_t* data) {
  return *reinterpret_cast<const int32_t*>(data);
}
}  // namespace

// The IA32 disassembler implementation.
class DisassemblerIA32 {
 public:
  DisassemblerIA32(
      const NameConverter& converter,
      Disassembler::UnimplementedOpcodeAction unimplemented_opcode_action)
      : converter_(converter),
        vex_byte0_(0),
        vex_byte1_(0),
        vex_byte2_(0),
        instruction_table_(InstructionTable::get_instance()),
        tmp_buffer_pos_(0),
        unimplemented_opcode_action_(unimplemented_opcode_action) {
    tmp_buffer_[0] = '\0';
  }

  virtual ~DisassemblerIA32() {}

  // Writes one disassembled instruction into 'buffer' (0-terminated).
  // Returns the length of the disassembled machine instruction in bytes.
  int InstructionDecode(v8::base::Vector<char> buffer, uint8_t* instruction);

 private:
  const NameConverter& converter_;
  uint8_t vex_byte0_;  // 0xC4 or 0xC5
  uint8_t vex_byte1_;
  uint8_t vex_byte2_;  // only for 3 bytes vex prefix
  InstructionTable* instruction_table_;
  v8::base::EmbeddedVector<char, 128> tmp_buffer_;
  unsigned int tmp_buffer_pos_;
  Disassembler::UnimplementedOpcodeAction unimplemented_opcode_action_;

  enum {
    eax = 0,
    ecx = 1,
    edx = 2,
    ebx = 3,
    esp = 4,
    ebp = 5,
    esi = 6,
    edi = 7
  };

  enum ShiftOpcodeExtension {
    kROL = 0,
    kROR = 1,
    kRCL = 2,
    kRCR = 3,
    kSHL = 4,
    KSHR = 5,
    kSAR = 7
  };

  bool vex_128() {
    DCHECK(vex_byte0_ == 0xC4 || vex_byte0_ == 0xC5);
    uint8_t checked = vex_byte0_ == 0xC4 ? vex_byte2_ : vex_byte1_;
    return (checked & 4) == 0;
  }

  bool vex_none() {
    DCHECK(vex_byte0_ == 0xC4 || vex_byte0_ == 0xC5);
    uint8_t checked = vex_byte0_ == 0xC4 ? vex_byte2_ : vex_byte1_;
    return (checked & 3) == 0;
  }

  bool vex_66() {
    DCHECK(vex_byte0_ == 0xC4 || vex_byte0_ == 0xC5);
    uint8_t checked = vex_byte0_ == 0xC4 ? vex_byte2_ : vex_byte1_;
    return (checked & 3) == 1;
  }

  bool vex_f3() {
    DCHECK(vex_byte0_ == 0xC4 || vex_byte0_ == 0xC5);
    uint8_t checked = vex_byte0_ == 0xC4 ? vex_byte2_ : vex_byte1_;
    return (checked & 3) == 2;
  }

  bool vex_f2() {
    DCHECK(vex_byte0_ == 0xC4 || vex_byte0_ == 0xC5);
    uint8_t checked = vex_byte0_ == 0xC4 ? vex_byte2_ : vex_byte1_;
    return (checked & 3) == 3;
  }

  bool vex_w() {
    if (vex_byte0_ == 0xC5) return false;
    return (vex_byte2_ & 0x80) != 0;
  }

  bool vex_0f() {
    if (vex_byte0_ == 0xC5) return true;
    return (vex_byte1_ & 3) == 1;
  }

  bool vex_0f38() {
    if (vex_byte0_ == 0xC5) return false;
    return (vex_byte1_ & 3) == 2;
  }

  bool vex_0f3a() {
    if (vex_byte0_ == 0xC5) return false;
    return (vex_byte1_ & 3) == 3;
  }

  int vex_vreg() {
    DCHECK(vex_byte0_ == 0xC4 || vex_byte0_ == 0xC5);
    uint8_t checked = vex_byte0_ == 0xC4 ? vex_byte2_ : vex_byte1_;
    return ~(checked >> 3) & 0xF;
  }

  char float_size_code() { return "sd"[vex_w()]; }

  const char* NameOfCPURegister(int reg) const {
    return converter_.NameOfCPURegister(reg);
  }

  const char* NameOfByteCPURegister(int reg) const {
    return converter_.NameOfByteCPURegister(reg);
  }

  const char* NameOfXMMRegister(int reg) const {
    return converter_.NameOfXMMRegister(reg);
  }

  const char* NameOfAddress(uint8_t* addr) const {
    return converter_.NameOfAddress(addr);
  }

  // Disassembler helper functions.
  static void get_modrm(uint8_t data, int* mod, int* regop, int* rm) {
    *mod = (data >> 6) & 3;
    *regop = (data & 0x38) >> 3;
    *rm = data & 7;
  }

  static void get_sib(uint8_t data, int* scale, int* index, int* base) {
    *scale = (data >> 6) & 3;
    *index = (data >> 3) & 7;
    *base = data & 7;
  }

  using RegisterNameMapping = const char* (DisassemblerIA32::*)(int reg) const;

  int PrintRightOperandHelper(uint8_t* modrmp,
                              RegisterNameMapping register_name);
  int PrintRightOperand(uint8_t* modrmp);
  int PrintRightByteOperand(uint8_t* modrmp);
  int PrintRightXMMOperand(uint8_t* modrmp);
  int PrintOperands(const char* mnem, OperandOrder op_order, uint8_t* data);
  int PrintImmediateOp(uint8_t* data);
  int F7Instruction(uint8_t* data);
  int D1D3C1Instruction(uint8_t* data);
  int JumpShort(uint8_t* data);
  int JumpConditional(uint8_t* data, const char* comment);
  int JumpConditionalShort(uint8_t* data, const char* comment);
  int SetCC(uint8_t* data);
  int CMov(uint8_t* data);
  int FPUInstruction(uint8_t* data);
  int MemoryFPUInstruction(int escape_opcode, int regop, uint8_t* modrm_start);
  int RegisterFPUInstruction(int escape_opcode, uint8_t modrm_byte);
  int AVXInstruction(uint8_t* data);
  PRINTF_FORMAT(2, 3) void AppendToBuffer(const char* format, ...);

  void UnimplementedInstruction() {
    if (unimplemented_opcode_action_ ==
        Disassembler::kAbortOnUnimplementedOpcode) {
      FATAL("Unimplemented instruction in disassembler");
    } else {
      AppendToBuffer("'Unimplemented instruction'");
    }
  }
};

void DisassemblerIA32::AppendToBuffer(const char* format, ...) {
  v8::base::Vector<char> buf = tmp_buffer_ + tmp_buffer_pos_;
  va_list args;
  va_start(args, format);
  int result = v8::base::VSNPrintF(buf, format, args);
  va_end(args);
  tmp_buffer_pos_ += result;
}

int DisassemblerIA32::PrintRightOperandHelper(
    uint8_t* modrmp, RegisterNameMapping direct_register_name) {
  int mod, regop, rm;
  get_modrm(*modrmp, &mod, &regop, &rm);
  RegisterNameMapping register_name =
      (mod == 3) ? direct_register_name : &DisassemblerIA32::NameOfCPURegister;
  switch (mod) {
    case 0:
      if (rm == ebp) {
        AppendToBuffer("[0x%x]", Imm32(modrmp + 1));
        return 5;
      } else if (rm == esp) {
        uint8_t sib = *(modrmp + 1);
        int scale, index, base;
        get_sib(sib, &scale, &index, &base);
        if (index == esp && base == esp && scale == 0 /*times_1*/) {
          AppendToBuffer("[%s]", (this->*register_name)(rm));
          return 2;
        } else if (base == ebp) {
          int32_t disp = Imm32(modrmp + 2);
          AppendToBuffer("[%s*%d%s0x%x]", (this->*register_name)(index),
                         1 << scale, disp < 0 ? "-" : "+",
                         disp < 0 ? -disp : disp);
          return 6;
        } else if (index != esp && base != ebp) {
          // [base+index*scale]
          AppendToBuffer("[%s+%s*%d]", (this->*register_name)(base),
                         (this->*register_name)(index), 1 << scale);
          return 2;
        } else {
          UnimplementedInstruction();
          return 1;
        }
      }
      AppendToBuffer("[%s]", (this->*register_name)(rm));
      return 1;
    case 1:  // fall through
    case 2: {
      if (rm == esp) {
        uint8_t sib = *(modrmp + 1);
        int scale, index, base;
        get_sib(sib, &scale, &index, &base);
        int disp = mod == 2 ? Imm32(modrmp + 2) : Imm8(modrmp + 2);
        if (index == base && index == rm /*esp*/ && scale == 0 /*times_1*/) {
          AppendToBuffer("[%s%s0x%x]", (this->*register_name)(rm),
                         disp < 0 ? "-" : "+", disp < 0 ? -disp : disp);
        } else {
          AppendToBuffer("[%s+%s*%d%s0x%x]", (this->*register_name)(base),
                         (this->*register_name)(index), 1 << scale,
                         disp < 0 ? "-" : "+", disp < 0 ? -disp : disp);
        }
        return mod == 2 ? 6 : 3;
      }
      // No sib.
      int disp = mod == 2 ? Imm32(modrmp + 1) : Imm8(modrmp + 1);
      AppendToBuffer("[%s%s0x%x]", (this->*register_name)(rm),
                     disp < 0 ? "-" : "+", disp < 0 ? -disp : disp);
      return mod == 2 ? 5 : 2;
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

int DisassemblerIA32::PrintRightOperand(uint8_t* modrmp) {
  return PrintRightOperandHelper(modrmp, &DisassemblerIA32::NameOfCPURegister);
}

int DisassemblerIA32::PrintRightByteOperand(uint8_t* modrmp) {
  return PrintRightOperandHelper(modrmp,
                                 &DisassemblerIA32::NameOfByteCPURegister);
}

int DisassemblerIA32::PrintRightXMMOperand(uint8_t* modrmp) {
  return PrintRightOperandHelper(modrmp, &DisassemblerIA32::NameOfXMMRegister);
}

// Returns number of bytes used including the current *data.
// Writes instruction's mnemonic, left and right operands to 'tmp_buffer_'.
int DisassemblerIA32::PrintOperands(const char* mnem, OperandOrder op_order,
                                    uint8_t* data) {
  uint8_t modrm = *data;
  int mod, regop, rm;
  get_modrm(modrm, &mod, &regop, &rm);
  int advance = 0;
  switch (op_order) {
    case REG_OPER_OP_ORDER: {
      AppendToBuffer("%s %s,", mnem, NameOfCPURegister(regop));
      advance = PrintRightOperand(data);
      break;
    }
    case OPER_REG_OP_ORDER: {
      AppendToBuffer("%s ", mnem);
      advance = PrintRightOperand(data);
      AppendToBuffer(",%s", NameOfCPURegister(regop));
      break;
    }
    default:
      UNREACHABLE();
  }
  return advance;
}

// Returns number of bytes used by machine instruction, including *data byte.
// Writes immediate instructions to 'tmp_buffer_'.
int DisassemblerIA32::PrintImmediateOp(uint8_t* data) {
  bool sign_extension_bit = (*data & 0x02) != 0;
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
  AppendToBuffer("%s ", mnem);
  int count = PrintRightOperand(data + 1);
  if (sign_extension_bit) {
    AppendToBuffer(",0x%x", *(data + 1 + count));
    return 1 + count + 1 /*int8*/;
  } else {
    AppendToBuffer(",0x%x", Imm32(data + 1 + count));
    return 1 + count + 4 /*int32_t*/;
  }
}

// Returns number of bytes used, including *data.
int DisassemblerIA32::F7Instruction(uint8_t* data) {
  DCHECK_EQ(0xF7, *data);
  uint8_t modrm = *++data;
  int mod, regop, rm;
  get_modrm(modrm, &mod, &regop, &rm);
  const char* mnem = "";
  switch (regop) {
    case 0:
      mnem = "test";
      break;
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
  AppendToBuffer("%s ", mnem);
  int count = PrintRightOperand(data);
  if (regop == 0) {
    AppendToBuffer(",0x%x", Imm32(data + count));
    count += 4;
  }
  return 1 + count;
}

int DisassemblerIA32::D1D3C1Instruction(uint8_t* data) {
  uint8_t op = *data;
  DCHECK(op == 0xD1 || op == 0xD3 || op == 0xC1);
  uint8_t modrm = *++data;
  int mod, regop, rm;
  get_modrm(modrm, &mod, &regop, &rm);
  int imm8 = -1;
  const char* mnem = "";
  switch (regop) {
    case kROL:
      mnem = "rol";
      break;
    case kROR:
      mnem = "ror";
      break;
    case kRCL:
      mnem = "rcl";
      break;
    case kRCR:
      mnem = "rcr";
      break;
    case kSHL:
      mnem = "shl";
      break;
    case KSHR:
      mnem = "shr";
      break;
    case kSAR:
      mnem = "sar";
      break;
    default:
      UnimplementedInstruction();
  }
  AppendToBuffer("%s ", mnem);
  int count = PrintRightOperand(data);
  if (op == 0xD1) {
    imm8 = 1;
  } else if (op == 0xC1) {
    imm8 = *(data + 1);
    count++;
  } else if (op == 0xD3) {
    // Shift/rotate by cl.
  }
  if (imm8 >= 0) {
    AppendToBuffer(",%d", imm8);
  } else {
    AppendToBuffer(",cl");
  }
  return 1 + count;
}

// Returns number of bytes used, including *data.
int DisassemblerIA32::JumpShort(uint8_t* data) {
  DCHECK_EQ(0xEB, *data);
  uint8_t b = *(data + 1);
  uint8_t* dest = data + static_cast<int8_t>(b) + 2;
  AppendToBuffer("jmp %s", NameOfAddress(dest));
  return 2;
}

// Returns number of bytes used, including *data.
int DisassemblerIA32::JumpConditional(uint8_t* data, const char* comment) {
  DCHECK_EQ(0x0F, *data);
  uint8_t cond = *(data + 1) & 0x0F;
  uint8_t* dest = data + Imm32(data + 2) + 6;
  const char* mnem = jump_conditional_mnem[cond];
  AppendToBuffer("%s %s", mnem, NameOfAddress(dest));
  if (comment != nullptr) {
    AppendToBuffer(", %s", comment);
  }
  return 6;  // includes 0x0F
}

// Returns number of bytes used, including *data.
int DisassemblerIA32::JumpConditionalShort(uint8_t* data, const char* comment) {
  uint8_t cond = *data & 0x0F;
  uint8_t b = *(data + 1);
  uint8_t* dest = data + static_cast<int8_t>(b) + 2;
  const char* mnem = jump_conditional_mnem[cond];
  AppendToBuffer("%s %s", mnem, NameOfAddress(dest));
  if (comment != nullptr) {
    AppendToBuffer(", %s", comment);
  }
  return 2;
}

// Returns number of bytes used, including *data.
int DisassemblerIA32::SetCC(uint8_t* data) {
  DCHECK_EQ(0x0F, *data);
  uint8_t cond = *(data + 1) & 0x0F;
  const char* mnem = set_conditional_mnem[cond];
  AppendToBuffer("%s ", mnem);
  PrintRightByteOperand(data + 2);
  return 3;  // Includes 0x0F.
}

// Returns number of bytes used, including *data.
int DisassemblerIA32::CMov(uint8_t* data) {
  DCHECK_EQ(0x0F, *data);
  uint8_t cond = *(data + 1) & 0x0F;
  const char* mnem = conditional_move_mnem[cond];
  int op_size = PrintOperands(mnem, REG_OPER_OP_ORDER, data + 2);
  return 2 + op_size;  // includes 0x0F
}

const char* sf_str[4] = {"", "rl", "ra", "ll"};

int DisassemblerIA32::AVXInstruction(uint8_t* data) {
  uint8_t opcode = *data;
  uint8_t* current = data + 1;
  if (vex_66() && vex_0f38()) {
    int mod, regop, rm, vvvv = vex_vreg();
    get_modrm(*current, &mod, &regop, &rm);
    switch (opcode) {
      case 0x18:
        AppendToBuffer("vbroadcastss %s,", NameOfXMMRegister(regop));
        current += PrintRightXMMOperand(current);
        break;
      case 0x37:
        AppendToBuffer("vpcmpgtq %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        break;
      case 0xF7:
        AppendToBuffer("shlx %s,", NameOfCPURegister(regop));
        current += PrintRightOperand(current);
        AppendToBuffer(",%s", NameOfCPURegister(vvvv));
        break;
#define DECLARE_SSE_AVX_DIS_CASE(instruction, notUsed1, notUsed2, notUsed3, \
                                 opcode)                                    \
  case 0x##opcode: {                                                        \
    AppendToBuffer("v" #instruction " %s,%s,", NameOfXMMRegister(regop),    \
                   NameOfXMMRegister(vvvv));                                \
    current += PrintRightXMMOperand(current);                               \
    break;                                                                  \
  }

        SSSE3_INSTRUCTION_LIST(DECLARE_SSE_AVX_DIS_CASE)
        SSE4_INSTRUCTION_LIST(DECLARE_SSE_AVX_DIS_CASE)
#undef DECLARE_SSE_AVX_DIS_CASE
#define DECLARE_SSE_AVX_RM_DIS_CASE(instruction, notUsed1, notUsed2, notUsed3, \
                                    opcode)                                    \
  case 0x##opcode: {                                                           \
    AppendToBuffer("v" #instruction " %s,", NameOfXMMRegister(regop));         \
    current += PrintRightXMMOperand(current);                                  \
    break;                                                                     \
  }

        SSSE3_UNOP_INSTRUCTION_LIST(DECLARE_SSE_AVX_RM_DIS_CASE)
        SSE4_RM_INSTRUCTION_LIST(DECLARE_SSE_AVX_RM_DIS_CASE)
#undef DECLARE_SSE_AVX_RM_DIS_CASE

#define DISASSEMBLE_AVX2_BROADCAST(instruction, _1, _2, _3, code)     \
  case 0x##code:                                                      \
    AppendToBuffer("" #instruction " %s,", NameOfXMMRegister(regop)); \
    current += PrintRightXMMOperand(current);                         \
    break;
        AVX2_BROADCAST_LIST(DISASSEMBLE_AVX2_BROADCAST)
#undef DISASSEMBLE_AVX2_BROADCAST

      default: {
#define DECLARE_FMA_DISASM(instruction, _1, _2, _3, _4, _5, code)    \
  case 0x##code: {                                                   \
    AppendToBuffer(#instruction " %s,%s,", NameOfXMMRegister(regop), \
                   NameOfXMMRegister(vvvv));                         \
    current += PrintRightXMMOperand(current);                        \
    break;                                                           \
  }
        // Handle all the fma instructions here in the default branch since they
        // have the same opcodes but differ by rex_w.
        if (vex_w()) {
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
      case 0x08:
        AppendToBuffer("vroundps %s,", NameOfXMMRegister(regop));
        current += PrintRightXMMOperand(current);
        AppendToBuffer(",%d", Imm8_U(current));
        current++;
        break;
      case 0x09:
        AppendToBuffer("vroundpd %s,", NameOfXMMRegister(regop));
        current += PrintRightXMMOperand(current);
        AppendToBuffer(",%d", Imm8_U(current));
        current++;
        break;
      case 0x0a:
        AppendToBuffer("vroundss %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        AppendToBuffer(",%d", Imm8_U(current));
        current++;
        break;
      case 0x0b:
        AppendToBuffer("vroundsd %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        AppendToBuffer(",%d", Imm8_U(current));
        current++;
        break;
      case 0x0E:
        AppendToBuffer("vpblendw %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        AppendToBuffer(",%d", Imm8_U(current));
        current++;
        break;
      case 0x0F:
        AppendToBuffer("vpalignr %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        AppendToBuffer(",%d", Imm8_U(current));
        current++;
        break;
      case 0x14:
        AppendToBuffer("vpextrb ");
        current += PrintRightOperand(current);
        AppendToBuffer(",%s,%d", NameOfXMMRegister(regop), Imm8(current));
        current++;
        break;
      case 0x15:
        AppendToBuffer("vpextrw ");
        current += PrintRightOperand(current);
        AppendToBuffer(",%s,%d", NameOfXMMRegister(regop), Imm8(current));
        current++;
        break;
      case 0x16:
        AppendToBuffer("vpextrd ");
        current += PrintRightOperand(current);
        AppendToBuffer(",%s,%d", NameOfXMMRegister(regop), Imm8(current));
        current++;
        break;
      case 0x20:
        AppendToBuffer("vpinsrb %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightOperand(current);
        AppendToBuffer(",%d", Imm8(current));
        current++;
        break;
      case 0x21:
        AppendToBuffer("vinsertps %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        AppendToBuffer(",%d", Imm8(current));
        current++;
        break;
      case 0x22:
        AppendToBuffer("vpinsrd %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightOperand(current);
        AppendToBuffer(",%d", Imm8(current));
        current++;
        break;
      case 0x4A:
        AppendToBuffer("vblendvps %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        AppendToBuffer(",%s", NameOfXMMRegister(*current >> 4));
        break;
      case 0x4B:
        AppendToBuffer("vblendvps %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        AppendToBuffer(",%s", NameOfXMMRegister(*current >> 4));
        break;
      case 0x4C:
        AppendToBuffer("vpblendvb %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        AppendToBuffer(",%s", NameOfXMMRegister(*current >> 4));
        break;
      default:
        UnimplementedInstruction();
    }
  } else if (vex_f2() && vex_0f()) {
    int mod, regop, rm, vvvv = vex_vreg();
    get_modrm(*current, &mod, &regop, &rm);
    switch (opcode) {
      case 0x10:
        AppendToBuffer("vmovsd %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        break;
      case 0x11:
        AppendToBuffer("vmovsd ");
        current += PrintRightXMMOperand(current);
        AppendToBuffer(",%s", NameOfXMMRegister(regop));
        break;
      case 0x12:
        AppendToBuffer("vmovddup %s,", NameOfXMMRegister(regop));
        current += PrintRightXMMOperand(current);
        break;
      case 0x2c:
        AppendToBuffer("vcvttsd2si %s,", NameOfXMMRegister(regop));
        current += PrintRightXMMOperand(current);
        break;
      case 0x70:
        AppendToBuffer("vpshuflw %s,", NameOfXMMRegister(regop));
        current += PrintRightXMMOperand(current);
        AppendToBuffer(",%d", Imm8(current));
        current++;
        break;
      case 0x7C:
        AppendToBuffer("vhaddps %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        break;
#define DISASM_SSE2_INSTRUCTION_LIST_SD(instruction, _1, _2, opcode)     \
  case 0x##opcode:                                                       \
    AppendToBuffer("v" #instruction " %s,%s,", NameOfXMMRegister(regop), \
                   NameOfXMMRegister(vvvv));                             \
    current += PrintRightXMMOperand(current);                            \
    break;
        SSE2_INSTRUCTION_LIST_SD(DISASM_SSE2_INSTRUCTION_LIST_SD)
#undef DISASM_SSE2_INSTRUCTION_LIST_SD
      default:
        UnimplementedInstruction();
    }
  } else if (vex_f3() && vex_0f()) {
    int mod, regop, rm, vvvv = vex_vreg();
    get_modrm(*current, &mod, &regop, &rm);
    switch (opcode) {
      case 0x10:
        AppendToBuffer("vmovss %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        break;
      case 0x11:
        AppendToBuffer("vmovss ");
        current += PrintRightXMMOperand(current);
        AppendToBuffer(",%s", NameOfXMMRegister(regop));
        break;
      case 0x16:
        AppendToBuffer("vmovshdup %s,", NameOfXMMRegister(regop));
        current += PrintRightXMMOperand(current);
        break;
      case 0x2c:
        AppendToBuffer("vcvttss2si %s,", NameOfXMMRegister(regop));
        current += PrintRightXMMOperand(current);
        break;
      case 0x51:
        AppendToBuffer("vsqrtss %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        break;
      case 0x58:
        AppendToBuffer("vaddss %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        break;
      case 0x59:
        AppendToBuffer("vmulss %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        break;
      case 0x5a:
        AppendToBuffer("vcvtss2sd %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        break;
      case 0x5B:
        AppendToBuffer("vcvttps2dq %s,", NameOfXMMRegister(regop));
        current += PrintRightXMMOperand(current);
        break;
      case 0x5C:
        AppendToBuffer("vsubss %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        break;
      case 0x5D:

"""


```