Response: The user wants to understand the functionality of the C++ code in `v8/src/diagnostics/ia32/disasm-ia32.cc`. This file seems to be responsible for disassembling IA-32 (x86 32-bit) machine code.

Here's a breakdown of the thought process to summarize the code:

1. **Identify the core purpose:** The filename `disasm-ia32.cc` strongly suggests it's a disassembler for the IA-32 architecture. The `disasm` namespace further confirms this.

2. **Look for key data structures:** The code defines several `ByteMnemonic` arrays. These arrays appear to map byte values to instruction mnemonics and operand order. This is a common pattern in disassemblers.

3. **Analyze the `InstructionTable` class:** This class seems to be responsible for organizing the instruction information. The `Init()` method populates the `instructions_` array using the `ByteMnemonic` tables. This suggests a lookup table approach for instruction decoding.

4. **Examine the `DisassemblerIA32` class:** This class contains the main disassembling logic. The `InstructionDecode()` method is likely the entry point for disassembling a single instruction.

5. **Identify helper functions:**  Functions like `PrintRightOperand`, `PrintOperands`, `PrintImmediateOp`, `JumpConditional`, and `FPUInstruction` suggest the process of parsing operands and specific instruction types.

6. **Look for architecture-specific details:** The code uses IA-32 register names (eax, ecx, etc.), deals with ModR/M and SIB bytes, and handles FPU instructions. This confirms its IA-32 focus. The presence of AVX instruction handling indicates support for more modern extensions of the IA-32 architecture.

7. **Consider the relationship to JavaScript:**  V8 is a JavaScript engine. This disassembler is likely used for debugging and profiling JavaScript code by examining the generated machine code.

8. **Formulate the summary:** Combine the observations to create a concise description of the file's functionality.

9. **Construct a JavaScript example (if applicable):**  Demonstrate how the disassembler's output could be used in the context of JavaScript. This likely involves looking at how V8 exposes debugging or profiling information. The example provided in the user's prompt, which was in the final code, highlights how a debugger might show disassembled code.
这个C++源代码文件是V8 JavaScript引擎的一部分，专门用于**反汇编 (disassemble) IA-32 (x86 32位) 架构的机器码**。

具体来说，它的功能是：

1. **定义了IA-32指令的助记符 (mnemonics) 和操作数顺序:**  文件中定义了多个静态的 `ByteMnemonic` 结构体数组，例如 `two_operands_instr`、`zero_operands_instr` 等。这些数组将 IA-32 指令的字节码与对应的汇编助记符以及操作数的顺序关联起来。

2. **创建指令查找表:**  `InstructionTable` 类负责创建和管理一个查找表，该表将 IA-32 指令的第一个字节映射到包含指令助记符、类型和操作数顺序的 `InstructionDesc` 结构体。

3. **实现反汇编逻辑:** `DisassemblerIA32` 类包含了实际的反汇编逻辑。 `InstructionDecode` 方法接收一个指向机器码的指针，并将其反汇编成人类可读的汇编指令字符串。

4. **处理各种IA-32指令格式:**  代码中包含了处理不同指令格式的逻辑，例如：
    * 零操作数指令 (例如 `ret`, `nop`)
    * 双操作数指令 (例如 `add`, `mov`)
    * 带有立即数的指令
    * 跳转指令 (有条件和无条件)
    * FPU (浮点单元) 指令
    * SSE/AVX (SIMD扩展) 指令

5. **与外部组件交互:**  `DisassemblerIA32` 类依赖于 `NameConverter` 接口来获取寄存器和内存地址的名称。这允许在反汇编输出中使用更友好的名称。

**与 Javascript 的关系:**

这个文件是 V8 引擎的一部分，因此它直接关系到 JavaScript 的执行。当 V8 编译 JavaScript 代码时，它会生成机器码。  这个反汇编器可以用于：

* **调试 JavaScript 代码:**  开发者可以使用调试工具来查看 V8 生成的机器码，从而更深入地理解代码的执行过程和性能瓶颈。
* **性能分析:**  分析生成的机器码可以帮助理解 V8 如何优化 JavaScript 代码。
* **内部开发和维护:** V8 开发者可以使用反汇编器来验证代码生成器的正确性，或者分析特定的代码模式如何被编译。

**JavaScript 示例:**

虽然我们不能直接在 JavaScript 中调用这个 C++ 反汇编器，但是我们可以模拟在调试场景中看到的反汇编输出。

假设我们有以下 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

add(1, 2);
```

当 V8 执行这段代码时，`add` 函数会被编译成机器码。  一个调试器可能会显示类似下面的反汇编输出（注意，这只是一个简化的例子，实际输出会更复杂）：

```assembly
;;; Function add
0x12345678: push ebp                ; 保存旧的基址指针
0x12345679: mov ebp, esp            ; 设置新的基址指针
0x1234567b: mov eax, [ebp+0x8]      ; 将参数 a 加载到 eax 寄存器
0x1234567e: add eax, [ebp+0xc]      ; 将参数 b 加载到 eax 并相加
0x12345681: pop ebp                 ; 恢复旧的基址指针
0x12345682: ret                     ; 返回
```

在这个例子中，每一行左边是机器码的地址，中间是反汇编后的 IA-32 指令（例如 `push ebp`, `mov eax, [ebp+0x8]`, `add eax, [ebp+0xc]`, `ret`），右边是指令的注释。  `disasm-ia32.cc` 文件的功能就是生成中间这部分人类可读的汇编指令。

总结来说，`v8/src/diagnostics/ia32/disasm-ia32.cc` 是 V8 引擎中一个重要的组成部分，它负责将 IA-32 机器码转换成易于理解的汇编代码，这对于调试、性能分析和 V8 的内部开发至关重要。

Prompt: 
```
这是目录为v8/src/diagnostics/ia32/disasm-ia32.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能

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
        AppendToBuffer("vminss %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        break;
      case 0x5E:
        AppendToBuffer("vdivss %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        break;
      case 0x5F:
        AppendToBuffer("vmaxss %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        break;
      case 0x6f:
        AppendToBuffer("vmovdqu %s,", NameOfXMMRegister(regop));
        current += PrintRightOperand(current);
        break;
      case 0x70:
        AppendToBuffer("vpshufhw %s,", NameOfXMMRegister(regop));
        current += PrintRightXMMOperand(current);
        AppendToBuffer(",%d", Imm8(current));
        current++;
        break;
      case 0x7f:
        AppendToBuffer("vmovdqu ");
        current += PrintRightOperand(current);
        AppendToBuffer(",%s", NameOfXMMRegister(regop));
        break;
      case 0xE6:
        AppendToBuffer("vcvtdq2pd %s,", NameOfXMMRegister(regop));
        current += PrintRightXMMOperand(current);
        break;
      default:
        UnimplementedInstruction();
    }
  } else if (vex_none() && vex_0f38()) {
    int mod, regop, rm, vvvv = vex_vreg();
    get_modrm(*current, &mod, &regop, &rm);
    const char* mnem = "?";
    switch (opcode) {
      case 0xF2:
        AppendToBuffer("andn %s,%s,", NameOfCPURegister(regop),
                       NameOfCPURegister(vvvv));
        current += PrintRightOperand(current);
        break;
      case 0xF5:
        AppendToBuffer("bzhi %s,", NameOfCPURegister(regop));
        current += PrintRightOperand(current);
        AppendToBuffer(",%s", NameOfCPURegister(vvvv));
        break;
      case 0xF7:
        AppendToBuffer("bextr %s,", NameOfCPURegister(regop));
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
        AppendToBuffer("%s %s,", mnem, NameOfCPURegister(vvvv));
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
        AppendToBuffer("pdep %s,%s,", NameOfCPURegister(regop),
                       NameOfCPURegister(vvvv));
        current += PrintRightOperand(current);
        break;
      case 0xF6:
        AppendToBuffer("mulx %s,%s,", NameOfCPURegister(regop),
                       NameOfCPURegister(vvvv));
        current += PrintRightOperand(current);
        break;
      case 0xF7:
        AppendToBuffer("shrx %s,", NameOfCPURegister(regop));
        current += PrintRightOperand(current);
        AppendToBuffer(",%s", NameOfCPURegister(vvvv));
        break;
      default:
        UnimplementedInstruction();
    }
  } else if (vex_f3() && vex_0f38()) {
    int mod, regop, rm, vvvv = vex_vreg();
    get_modrm(*current, &mod, &regop, &rm);
    switch (opcode) {
      case 0xF5:
        AppendToBuffer("pext %s,%s,", NameOfCPURegister(regop),
                       NameOfCPURegister(vvvv));
        current += PrintRightOperand(current);
        break;
      case 0xF7:
        AppendToBuffer("sarx %s,", NameOfCPURegister(regop));
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
        AppendToBuffer("rorx %s,", NameOfCPURegister(regop));
        current += PrintRightOperand(current);
        AppendToBuffer(",%d", *current & 0x1F);
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
        AppendToBuffer("vmovups %s,", NameOfXMMRegister(regop));
        current += PrintRightXMMOperand(current);
        break;
      case 0x11:
        AppendToBuffer("vmovups ");
        current += PrintRightXMMOperand(current);
        AppendToBuffer(",%s", NameOfXMMRegister(regop));
        break;
      case 0x12:
        if (mod == 0b11) {
          AppendToBuffer("vmovhlps %s,%s,", NameOfXMMRegister(regop),
                         NameOfXMMRegister(vvvv));
        } else {
          AppendToBuffer("vmovlps %s,%s,", NameOfXMMRegister(regop),
                         NameOfXMMRegister(vvvv));
        }
        current += PrintRightXMMOperand(current);
        break;
      case 0x13:
        AppendToBuffer("vmovlps ");
        current += PrintRightXMMOperand(current);
        AppendToBuffer(",%s", NameOfXMMRegister(regop));
        break;
      case 0x14:
        AppendToBuffer("vunpcklps %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        break;
      case 0x16:
        AppendToBuffer("vmovhps %s,", NameOfXMMRegister(regop));
        current += PrintRightXMMOperand(current);
        break;
      case 0x17:
        AppendToBuffer("vmovhps ");
        current += PrintRightXMMOperand(current);
        AppendToBuffer(",%s", NameOfXMMRegister(regop));
        break;
      case 0x28:
        AppendToBuffer("vmovaps %s,", NameOfXMMRegister(regop));
        current += PrintRightXMMOperand(current);
        break;
      case 0x2e:
        AppendToBuffer("vucomiss %s,", NameOfXMMRegister(regop));
        current += PrintRightXMMOperand(current);
        break;
      case 0x50:
        AppendToBuffer("vmovmskps %s,%s", NameOfCPURegister(regop),
                       NameOfXMMRegister(rm));
        current++;
        break;
      case 0x51:
        AppendToBuffer("vsqrtps %s,", NameOfXMMRegister(regop));
        current += PrintRightXMMOperand(current);
        break;
      case 0x52:
        AppendToBuffer("vrsqrtps %s,", NameOfXMMRegister(regop));
        current += PrintRightXMMOperand(current);
        break;
      case 0x53:
        AppendToBuffer("vrcpps %s,", NameOfXMMRegister(regop));
        current += PrintRightXMMOperand(current);
        break;
      case 0x54:
        AppendToBuffer("vandps %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        break;
      case 0x55:
        AppendToBuffer("vandnps %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        break;
      case 0x56:
        AppendToBuffer("vorps %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        break;
      case 0x57:
        AppendToBuffer("vxorps %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        break;
      case 0x58:
        AppendToBuffer("vaddps %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        break;
      case 0x59:
        AppendToBuffer("vmulps %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        break;
      case 0x5A:
        AppendToBuffer("vcvtps2pd %s,", NameOfXMMRegister(regop));
        current += PrintRightXMMOperand(current);
        break;
      case 0x5B:
        AppendToBuffer("vcvtdq2ps %s,", NameOfXMMRegister(regop));
        current += PrintRightXMMOperand(current);
        break;
      case 0x5C:
        AppendToBuffer("vsubps %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        break;
      case 0x5D:
        AppendToBuffer("vminps %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        break;
      case 0x5E:
        AppendToBuffer("vdivps %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        break;
      case 0x5F:
        AppendToBuffer("vmaxps %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        break;
      case 0xC2: {
        AppendToBuffer("vcmpps %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        AppendToBuffer(", (%s)", cmp_pseudo_op[*current]);
        current++;
        break;
      }
      case 0xC6:
        AppendToBuffer("vshufps %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        AppendToBuffer(", %d", (*current) & 3);
        current += 1;
        break;
      default:
        UnimplementedInstruction();
    }
  } else if (vex_66() && vex_0f()) {
    int mod, regop, rm, vvvv = vex_vreg();
    get_modrm(*current, &mod, &regop, &rm);
    switch (opcode) {
      case 0x10:
        AppendToBuffer("vmovupd %s,", NameOfXMMRegister(regop));
        current += PrintRightXMMOperand(current);
        break;
      case 0x28:
        AppendToBuffer("vmovapd %s,", NameOfXMMRegister(regop));
        current += PrintRightXMMOperand(current);
        break;
      case 0x2e:
        AppendToBuffer("vucomisd %s,", NameOfXMMRegister(regop));
        current += PrintRightXMMOperand(current);
        break;
      case 0x50:
        AppendToBuffer("vmovmskpd %s,%s", NameOfCPURegister(regop),
                       NameOfXMMRegister(rm));
        current++;
        break;
      case 0x54:
        AppendToBuffer("vandpd %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        break;
      case 0x55:
        AppendToBuffer("vandnpd %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        break;
      case 0x56:
        AppendToBuffer("vorpd %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        break;
      case 0x57:
        AppendToBuffer("vxorpd %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        break;
      case 0x58:
        AppendToBuffer("vaddpd %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        break;
      case 0x59:
        AppendToBuffer("vmulpd %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        break;
      case 0x5A:
        AppendToBuffer("vcvtpd2ps %s,", NameOfXMMRegister(regop));
        current += PrintRightXMMOperand(current);
        break;
      case 0x5C:
        AppendToBuffer("vsubpd %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        break;
      case 0x5D:
        AppendToBuffer("vminpd %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        break;
      case 0x5E:
        AppendToBuffer("vdivpd %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        break;
      case 0x5F:
        AppendToBuffer("vmaxpd %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        break;
      case 0x6E:
        AppendToBuffer("vmovd %s,", NameOfXMMRegister(regop));
        current += PrintRightOperand(current);
        break;
      case 0x6f:
        AppendToBuffer("vmovdqa %s,", NameOfXMMRegister(regop));
        current += PrintRightOperand(current);
        break;
      case 0x70:
        AppendToBuffer("vpshufd %s,", NameOfXMMRegister(regop));
        current += PrintRightXMMOperand(current);
        AppendToBuffer(",%d", Imm8(current));
        current++;
        break;
      case 0x71:
        AppendToBuffer("vps%sw %s,%s", sf_str[regop / 2],
                       NameOfXMMRegister(vvvv), NameOfXMMRegister(rm));
        current++;
        AppendToBuffer(",%u", *current++);
        break;
      case 0x72:
        AppendToBuffer("vps%sd %s,%s", sf_str[regop / 2],
                       NameOfXMMRegister(vvvv), NameOfXMMRegister(rm));
        current++;
        AppendToBuffer(",%u", *current++);
        break;
      case 0x73:
        AppendToBuffer("vps%sq %s,%s", sf_str[regop / 2],
                       NameOfXMMRegister(vvvv), NameOfXMMRegister(rm));
        current++;
        AppendToBuffer(",%u", *current++);
        break;
      case 0x7E:
        AppendToBuffer("vmovd ");
        current += PrintRightOperand(current);
        AppendToBuffer(",%s", NameOfXMMRegister(regop));
        break;
      case 0xC2: {
        AppendToBuffer("vcmppd %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        AppendToBuffer(", (%s)", cmp_pseudo_op[*current]);
        current++;
        break;
      }
      case 0xC4:
        AppendToBuffer("vpinsrw %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightOperand(current);
        AppendToBuffer(",%d", Imm8(current));
        current++;
        break;
      case 0xC6:
        AppendToBuffer("vshufpd %s,%s,", NameOfXMMRegister(regop),
                       NameOfXMMRegister(vvvv));
        current += PrintRightXMMOperand(current);
        AppendToBuffer(",%d", Imm8(current));
        current++;
        break;
      case 0xD7:
        AppendToBuffer("vpmovmskb %s,%s", NameOfCPURegister(regop),
                       NameOfXMMRegister(rm));
        current++;
        break;
      case 0xE6:
        AppendToBuffer("vcvttpd2dq %s,", NameOfXMMRegister(regop));
        current += PrintRightXMMOperand(current);
        break;
#define DECLARE_SSE_AVX_DIS_CASE(instruction, notUsed1, notUsed2, opcode) \
  case 0x##opcode: {                                                      \
    AppendToBuffer("v" #instruction " %s,%s,", NameOfXMMRegister(regop),  \
                   NameOfXMMRegister(vvvv));                              \
    current += PrintRightXMMOperand(current);                             \
    break;                                                                \
  }

        SSE2_INSTRUCTION_LIST(DECLARE_SSE_AVX_DIS_CASE)
#undef DECLARE_SSE_AVX_DIS_CASE
      default:
        UnimplementedInstruction();
    }
  } else {
    UnimplementedInstruction();
  }

  return static_cast<int>(current - data);
}

// Returns number of bytes used, including *data.
int DisassemblerIA32::FPUInstruction(uint8_t* data) {
  uint8_t escape_opcode = *data;
  DCHECK_EQ(0xD8, escape_opcode & 0xF8);
  uint8_t modrm_byte = *(data + 1);

  if (modrm_byte >= 0xC0) {
    return RegisterFPUInstruction(escape_opcode, modrm_byte);
  } else {
    return MemoryFPUInstruction(escape_opcode, modrm_byte, data + 1);
  }
}

int DisassemblerIA32::MemoryFPUInstruction(int escape_opcode, int modrm_byte,
                                           uint8_t* modrm_start) {
  const char* mnem = "?";
  int regop = (modrm_byte >> 3) & 0x7;  // reg/op field of modrm byte.
  switch (escape_opcode) {
    case 0xD9:
      switch (regop) {
        case 0:
          mnem = "fld_s";
          break;
        case 2:
          mnem = "fst_s";
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
        case 1:
          mnem = "fisttp_d";
          break;
        case 2:
          mnem = "fst_d";
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

int DisassemblerIA32::RegisterFPUInstruction(int escape_opcode,
                                             uint8_t modrm_byte) {
  bool has_register = false;  // Is the FPU register encoded in modrm_byte?
  const char* mnem = "?";

  switch (escape_opcode) {
    case 0xD8:
      has_register = true;
      switch (modrm_byte & 0xF8) {
        case 0xC0:
          mnem = "fadd_i";
          break;
        case 0xE0:
          mnem = "fsub_i";
          break;
        case 0xC8:
          mnem = "fmul_i";
          break;
        case 0xF0:
          mnem = "fdiv_i";
          break;
        default:
          UnimplementedInstruction();
      }
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
            case 0xF4:
              mnem = "fxtract";
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
        case 0xD0:
          mnem = "fst";
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

// Mnemonics for instructions 0xF0 byte.
// Returns nullptr if the instruction is not handled here.
static const char* F0Mnem(uint8_t f0byte) {
  switch (f0byte) {
    case 0x0B:
      return "ud2";
    case 0x18:
      return "prefetch";
    case 0xA2:
      return "cpuid";
    case 0xBE:
      return "movsx_b";
    case 0xBF:
      return "movsx_w";
    case 0xB6:
      return "movzx_b";
    case 0xB7:
      return "movzx_w";
    case 0xAF:
      return "imul";
    case 0xA4:
      return "shld";
    case 0xA5:
      return "shld";
    case 0xAD:
      return "shrd";
    case 0xAC:
      return "shrd";  // 3-operand version.
    case 0xAB:
      return "bts";
    case 0xB0:
      return "cmpxchg_b";
    case 0xB1:
      return "cmpxchg";
    case 0xBC:
      return "bsf";
    case 0xBD:
      return "bsr";
    case 0xC7:
      return "cmpxchg8b";
    default:
      return nullptr;
  }
}

// Disassembled instruction '*instr' and writes it into 'out_buffer'.
int DisassemblerIA32::InstructionDecode(v8::base::Vector<char> out_buffer,
                                        uint8_t* instr) {
  tmp_buffer_pos_ = 0;  // starting to write as position 0
  uint8_t* data = instr;
  // Check for hints.
  const char* branch_hint = nullptr;
  // We use these two prefixes only with branch prediction
  if (*data == 0x3E /*ds*/) {
    branch_hint = "predicted taken";
    data++;
  } else if (*data == 0x2E /*cs*/) {
    branch_hint = "predicted not taken";
    data++;
  } else if (*data == 0xC4 && *(data + 1) >= 0xC0) {
    vex_byte0_ = *data;
    vex_byte1_ = *(data + 1);
    vex_byte2_ = *(data + 2);
    data += 3;
  } else if (*data == 0xC5 && *(data + 1) >= 0xC0) {
    vex_byte0_ = *data;
    vex_byte1_ = *(data + 1);
    data += 2;
  } else if (*data == 0xF0 /*lock*/) {
    AppendToBuffer("lock ");
    data++;
  }

  bool processed = true;  // Will be set to false if the current instruction
                          // is not in 'instructions' table.
  // Decode AVX instructions.
  if (vex_byte0_ != 0) {
    data += AVXInstruction(data);
  } else {
    const InstructionDesc& idesc = instruction_table_->Get(*data);
    switch (idesc.type) {
      case ZERO_OPERANDS_INSTR:
        AppendToBuffer("%s", idesc.mnem);
        data++;
        break;

      case TWO_OPERANDS_INSTR:
        data++;
        data += PrintOperands(idesc.mnem, idesc.op_order_, data);
        break;

      case JUMP_CONDITIONAL_SHORT_INSTR:
        data += JumpConditionalShort(data, branch_hint);
        break;

      case REGISTER_INSTR:
        AppendToBuffer("%s %s", idesc.mnem, NameOfCPURegister(*data & 0x07));
        data++;
        break;

      case MOVE_REG_INSTR: {
        uint8_t* addr = reinterpret_cast<uint8_t*>(Imm32(data + 1));
        AppendToBuffer("mov %s,%s", NameOfCPURegister(*data & 0x07),
                       NameOfAddress(addr));
        data += 5;
        break;
      }

      case CALL_JUMP_INSTR: {
        uint8_t* addr = data + Imm32(data + 1) + 5;
        AppendToBuffer("%s %s", idesc.mnem, NameOfAddress(addr));
        data += 5;
        break;
      }

      case SHORT_IMMEDIATE_INSTR: {
        uint8_t* addr = reinterpret_cast<uint8_t*>(Imm32(data + 1));
        AppendToBuffer("%s eax,%s", idesc.mnem, NameOfAddress(addr));
        data += 5;
        break;
      }

      case BYTE_IMMEDIATE_INSTR: {
        AppendToBuffer("%s al,0x%x", idesc.mnem, data[1]);
        data += 2;
        break;
      }

      case NO_INSTR:
        processed = false;
        break;

      default:
        UNIMPLEMENTED();  // This type is not implemented.
    }
  }
  //----------------------------
  if (!processed) {
    switch (*data) {
      case 0xC2:
        AppendToBuffer("ret 0x%x", Imm16_U(data + 1));
        data += 3;
        break;

      case 0x6B: {
        data++;
        data += PrintOperands("imul", REG_OPER_OP_ORDER, data);
        AppendToBuffer(",%d", *data);
        data++;
      } break;

      case 0x69: {
        data++;
        data += PrintOperands("imul", REG_OPER_OP_ORDER, data);
        AppendToBuffer(",%d", Imm32(data));
        data += 4;
      } break;

      case 0xF6: {
        data++;
        int mod, regop, rm;
        get_modrm(*data, &mod, &regop, &rm);
        if (regop == eax) {
          AppendToBuffer("test_b ");
          data += PrintRightByteOperand(data);
          int32_t imm = *data;
          AppendToBuffer(",0x%x", imm);
          data++;
        } else {
          UnimplementedInstruction();
        }
      } break;

      case 0x81:  // fall through
      case 0x83:  // 0x81 with sign extension bit set
        data += PrintImmediateOp(data);
        break;

      case 0x0F: {
        uint8_t f0byte = data[1];
        const char* f0mnem = F0Mnem(f0byte);
        int mod, regop, rm;
        // Not every instruction use this, and it is safe to index data+2 as all
        // instructions are at least 3 bytes with operands.
        get_modrm(*(data + 2), &mod, &regop, &rm);
        if (f0byte == 0x12) {
          data += 2;
          if (mod == 0b11) {
            AppendToBuffer("movhlps %s,", NameOfXMMRegister(regop));
          } else {
            AppendToBuffer("movlps %s,", NameOfXMMRegister(regop));
          }
          data += PrintRightXMMOperand(data);
        } else if (f0byte == 0x13) {
          data += 2;
          AppendToBuffer("movlps ");
          data += PrintRightXMMOperand(data);
          AppendToBuffer(",%s", NameOfXMMRegister(regop));
        } else if (f0byte == 0x14) {
          data += 2;
          AppendToBuffer("unpcklps %s,", NameOfXMMRegister(regop));
          data += PrintRightXMMOperand(data);
        } else if (f0byte == 0x16) {
          data += 2;
          AppendToBuffer("movhps %s,", NameOfXMMRegister(regop));
          data += PrintRightXMMOperand(data);
        } else if (f0byte == 0x17) {
          data += 2;
          AppendToBuffer("movhps ");
          data += PrintRightXMMOperand(data);
          AppendToBuffer(",%s", NameOfXMMRegister(regop));
        } else if (f0byte == 0x18) {
          data += 2;
          const char* suffix[] = {"nta", "1", "2", "3"};
          AppendToBuffer("%s%s ", f0mnem, suffix[regop & 0x03]);
          data += PrintRightOperand(data);
        } else if (f0byte == 0x1F && data[2] == 0) {
          AppendToBuffer("nop");  // 3 byte nop.
          data += 3;
        } else if (f0byte == 0x1F && data[2] == 0x40 && data[3] == 0) {
          AppendToBuffer("nop");  // 4 byte nop.
          data += 4;
        } else if (f0byte == 0x1F && data[2] == 0x44 && data[3] == 0 &&
                   data[4] == 0) {
          AppendToBuffer("nop");  // 5 byte nop.
          data += 5;
        } else if (f0byte == 0x1F && data[2] == 0x80 && data[3] == 0 &&
                   data[4] == 0 && data[5] == 0 && data[6] == 0) {
          AppendToBuffer("nop");  // 7 byte nop.
          data += 7;
        } else if (f0byte == 0x1F && data[2] == 0x84 && data[3] == 0 &&
                   data[4] == 0 && data[5] == 0 && data[6] == 0 &&
                   data[7] == 0) {
          AppendToBuffer("nop");  // 8 byte nop.
          data += 8;
        } else if (f0byte == 0x0B || f0byte == 0xA2 || f0byte == 0x31) {
          AppendToBuffer("%s", f0mnem);
          data += 2;
        } else if (f0byte == 0x28) {
          data += 2;
          AppendToBuffer("movaps %s,%s", NameOfXMMRegister(regop),
                         NameOfXMMRegister(rm));
          data++;
        } else if (f0byte == 0x10 || f0byte == 0x11) {
          data += 2;
          // movups xmm, xmm/m128
          // movups xmm/m128, xmm
          AppendToBuffer("movups ");
          if (f0byte == 0x11) {
            data += PrintRightXMMOperand(data);
            AppendToBuffer(",%s", NameOfXMMRegister(regop));
          } else {
            AppendToBuffer("%s,", NameOfXMMRegister(regop));
            data += PrintRightXMMOperand(data);
          }
        } else if (f0byte == 0x2E) {
          data += 2;
          AppendToBuffer("ucomiss %s,", NameOfXMMRegister(regop));
          data += PrintRightXMMOperand(data);
        } else if (f0byte >= 0x51 && f0byte <= 0x5F) {
          const char* const pseudo_op[] = {
              "sqrtps",   "rsqrtps", "rcpps", "andps", "andnps",
              "orps",     "xorps",   "addps", "mulps", "cvtps2pd",
              "cvtdq2ps", "subps",   "minps", "divps", "maxps",
          };

          data += 2;
          AppendToBuffer("%s %s,", pseudo_op[f0byte - 0x51],
                         NameOfXMMRegister(regop));
          data += PrintRightXMMOperand(data);
        } else if (f0byte == 0x50) {
          data += 2;
          AppendToBuffer("movmskps %s,%s", NameOfCPURegister(regop),
                         NameOfXMMRegister(rm));
          data++;
        } else if (f0byte == 0xC0) {
          data += 2;
          data += PrintOperands("xadd_b", OPER_REG_OP_ORDER, data);
        } else if (f0byte == 0xC1) {
          data += 2;
          data += PrintOperands("xadd", OPER_REG_OP_ORDER, data);
        } else if (f0byte == 0xC2) {
          data += 2;
          AppendToBuffer("cmpps %s, ", NameOfXMMRegister(regop));
          data += PrintRightXMMOperand(data);
          AppendToBuffer(", (%s)", cmp_pseudo_op[*data]);
          data++;
        } else if (f0byte == 0xC6) {
          // shufps xmm, xmm/m128, imm8
          data += 2;
          int8_t imm8 = static_cast<int8_t>(data[1]);
          AppendToBuffer("shufps %s,%s,%d", NameOfXMMRegister(rm),
                         NameOfXMMRegister(regop), static_cast<int>(imm8));
          data += 2;
        } else if (f0byte >= 0xC8 && f0byte <= 0xCF) {
          // bswap
          data += 2;
          int reg = f0byte - 0xC8;
          AppendToBuffer("bswap %s", NameOfCPURegister(reg));
        } else if ((f0byte & 0xF0) == 0x80) {
          data += JumpConditional(data, branch_hint);
        } else if (f0byte == 0xBE || f0byte == 0xBF || f0byte == 0xB6 ||
                   f0byte == 0xB7 || f0byte == 0xAF) {
          data += 2;
          data += PrintOperands(f0mnem, REG_OPER_OP_ORDER, data);
        } else if ((f0byte & 0xF0) == 0x90) {
          data += SetCC(data);
        } else if ((f0byte & 0xF0) == 0x40) {
          data += CMov(data);
        } else if (f0byte == 0xA4 || f0byte == 0xAC) {
          // shld, shrd
          data += 2;
          AppendToBuffer("%s ", f0mnem);
          int8_t imm8 = static_cast<int8_t>(data[1]);
          data += 2;
          AppendToBuffer("%s,%s,%d", NameOfCPURegister(rm),
   
"""


```