Response: The user wants a summary of the functionality of the C++ code file `v8/src/diagnostics/mips64/disasm-mips64.cc`. The file seems to be related to disassembling MIPS64 instructions.

Here's a breakdown of the thought process:

1. **Identify the core purpose:** The filename and the initial comments clearly indicate this file implements a disassembler for the MIPS64 architecture. The core function is to take raw byte code and translate it into a human-readable assembly representation.

2. **Key Class:** The `Decoder` class is the central component. It holds the logic for decoding and formatting individual instructions.

3. **Input and Output:** The `InstructionDecode` method takes raw instruction bytes as input and writes the disassembled output to a buffer. The `Disassembler` class (mentioned in the comments but not in the provided snippet) likely uses the `Decoder`.

4. **Name Conversion:**  The code mentions a `NameConverter`. This is a crucial part of a disassembler. It's responsible for making the output more understandable by:
    * Converting register numbers to symbolic names (e.g., `$r0`, `$sp`).
    * Potentially looking up symbolic names for memory addresses (function names, global variables).

5. **Instruction Decoding Logic:**  The code has many `DecodeType...` functions. This suggests a structure where instructions are categorized by their format or type, and specific decoding logic is applied to each category.

6. **Formatting:** The `Format` and `FormatOption` functions handle the presentation of the disassembled instructions. They use format strings to control the order and representation of operands, immediate values, etc.

7. **Immediate Values:**  There are many `PrintImm...` functions. These handle the extraction and formatting of immediate values of different sizes and types (signed, unsigned, hexadecimal).

8. **Relationship to JavaScript:** V8 is the JavaScript engine. This disassembler is used for debugging and introspection of the compiled JavaScript code. When JavaScript code is executed, V8 compiles it to native machine code (in this case, MIPS64). This disassembler can be used to examine that generated code.

9. **JavaScript Example (Conceptual):**  While the C++ code itself doesn't *execute* JavaScript, its output represents the machine code that *does*. A JavaScript example demonstrating the *need* for such a tool would involve showing a piece of JavaScript code and then stating that the disassembler is used to understand the low-level MIPS64 instructions generated for it. It's impossible to provide the exact MIPS64 output without knowing the specific V8 version and optimization levels.

10. **Structure of the Response:**  Organize the summary into logical sections: core functionality, key components, connection to JavaScript, and a JavaScript example.

11. **Refine and Clarify:** Ensure the language is clear and concise. Explain technical terms like "disassembler" and "immediate value" if needed for a broader audience. Emphasize the debugging and introspection use case.
这个C++源代码文件 `disasm-mips64.cc` 的主要功能是 **反汇编 (Disassemble) MIPS64 架构的机器码指令**。

更具体地说，它的作用是将 MIPS64 的二进制指令解码成人类可读的汇编语言格式。 这个过程对于理解程序在底层是如何执行的，以及进行调试和性能分析非常重要。

以下是代码中体现的功能点：

* **`Decoder` 类:**  这是核心的解码器类，负责读取机器码指令并将其转换为可读的汇编表示。
* **`InstructionDecode` 方法:**  `Decoder` 类的关键方法，它接收指向指令的指针，解码该指令，并将反汇编后的结果写入到一个缓冲区。
* **格式化输出:** 代码中包含大量的 `Print...` 函数，用于格式化输出反汇编结果，例如打印寄存器名、立即数、内存地址等。
* **`NameConverter` 类 (在头文件中定义):**  虽然没有在这个部分的代码中直接看到 `NameConverter` 的实现，但从注释和 `Decoder` 类的构造函数可以看出，它负责将寄存器编号转换为易于理解的名称，并可能进行符号查找以解析内存地址。
* **处理不同指令类型:** 代码中包含大量的 `DecodeType...` 函数，每个函数负责解码特定类型的 MIPS64 指令。 这表明代码能够处理 MIPS64 指令集中的多种指令格式。
* **处理立即数:** 代码能够提取和打印各种大小和类型的立即数 (immediate values)。
* **错误处理 (有限):**  `Unknown` 函数用于处理无法识别的指令，简单地输出 "unknown"。

**与 JavaScript 的关系以及 JavaScript 示例:**

这个文件是 V8 JavaScript 引擎的一部分。V8 引擎会将 JavaScript 代码编译成机器码以提高执行效率。 在 MIPS64 架构上运行 JavaScript 时，V8 生成的机器码就是 MIPS64 指令。

`disasm-mips64.cc` 提供的反汇编功能可以用于 **检查 V8 引擎为 JavaScript 代码生成的具体 MIPS64 指令**。 这对于理解 V8 的代码生成策略、进行性能优化以及调试底层问题非常有用。

**JavaScript 示例 (概念性):**

假设我们有以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
console.log(result);
```

当 V8 引擎执行这段代码时，它会将 `add` 函数编译成一系列 MIPS64 指令。  `disasm-mips64.cc` 提供的功能可以用来查看这些指令，例如：

```assembly
// (这只是一个概念性的例子，实际生成的指令会更复杂，并且依赖于 V8 版本和优化级别)
0x12345678:  addi    $t0, $a0, $a1     // 将参数 a 和 b 相加，结果放入 $t0
0x1234567c:  move    $v0, $t0          // 将结果移动到返回值寄存器 $v0
0x12345680:  jr      $ra               // 返回
```

**解释:**

* 上面的汇编代码片段表示 `add` 函数可能的 MIPS64 实现。
* `addi` 指令执行加法操作。
* `$a0` 和 `$a1` 通常用于传递函数参数。
* `$v0` 通常用于存储函数返回值。
* `jr $ra` 是跳转到返回地址的指令。

**如何使用 (不是 `disasm-mips64.cc` 本身，而是 V8 提供的调试工具):**

在实际开发中，你不会直接编译和运行 `disasm-mips64.cc`。  V8 引擎提供了内置的调试和代码生成信息查看工具，你可以通过特定的命令行标志来查看生成的机器码。  例如，在使用 `d8` (V8 的 shell) 运行时，可能会有类似以下的标志 (具体标志可能因 V8 版本而异)：

```bash
d8 --print-code my_script.js
```

这个命令可能会输出 V8 为 `my_script.js` 生成的机器码，而 `disasm-mips64.cc` 中的代码就是用于将这些机器码转换为可读汇编的底层逻辑。

**总结:**

`v8/src/diagnostics/mips64/disasm-mips64.cc` 是 V8 引擎中用于反汇编 MIPS64 机器码的关键组件，它使得开发者能够理解 V8 为 JavaScript 代码生成的底层指令，从而进行更深入的分析和调试。

Prompt: 
```
这是目录为v8/src/diagnostics/mips64/disasm-mips64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// A Disassembler object is used to disassemble a block of code instruction by
// instruction. The default implementation of the NameConverter object can be
// overriden to modify register names or to do symbol lookup on addresses.
//
// The example below will disassemble a block of code and print it to stdout.
//
//   NameConverter converter;
//   Disassembler d(converter);
//   for (uint8_t* pc = begin; pc < end;) {
//     v8::base::EmbeddedVector<char, 256> buffer;
//     uint8_t* prev_pc = pc;
//     pc += d.InstructionDecode(buffer, pc);
//     printf("%p    %08x      %s\n",
//            prev_pc, *reinterpret_cast<int32_t*>(prev_pc), buffer);
//   }
//
// The Disassembler class also has a convenience method to disassemble a block
// of code into a FILE*, meaning that the above functionality could also be
// achieved by just calling Disassembler::Disassemble(stdout, begin, end);

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#if V8_TARGET_ARCH_MIPS64

#include "src/base/platform/platform.h"
#include "src/base/strings.h"
#include "src/base/vector.h"
#include "src/codegen/macro-assembler.h"
#include "src/codegen/mips64/constants-mips64.h"
#include "src/diagnostics/disasm.h"

namespace v8 {
namespace internal {

//------------------------------------------------------------------------------

// Decoder decodes and disassembles instructions into an output buffer.
// It uses the converter to convert register names and call destinations into
// more informative description.
class Decoder {
 public:
  Decoder(const disasm::NameConverter& converter,
          v8::base::Vector<char> out_buffer)
      : converter_(converter), out_buffer_(out_buffer), out_buffer_pos_(0) {
    out_buffer_[out_buffer_pos_] = '\0';
  }

  ~Decoder() {}

  Decoder(const Decoder&) = delete;
  Decoder& operator=(const Decoder&) = delete;

  // Writes one disassembled instruction into 'buffer' (0-terminated).
  // Returns the length of the disassembled machine instruction in bytes.
  int InstructionDecode(uint8_t* instruction);

 private:
  // Bottleneck functions to print into the out_buffer.
  void PrintChar(const char ch);
  void Print(const char* str);

  // Printing of common values.
  void PrintRegister(int reg);
  void PrintFPURegister(int freg);
  void PrintMSARegister(int wreg);
  void PrintFPUStatusRegister(int freg);
  void PrintMSAControlRegister(int creg);
  void PrintRs(Instruction* instr);
  void PrintRt(Instruction* instr);
  void PrintRd(Instruction* instr);
  void PrintFs(Instruction* instr);
  void PrintFt(Instruction* instr);
  void PrintFd(Instruction* instr);
  void PrintSa(Instruction* instr);
  void PrintLsaSa(Instruction* instr);
  void PrintSd(Instruction* instr);
  void PrintSs1(Instruction* instr);
  void PrintSs2(Instruction* instr);
  void PrintSs3(Instruction* instr);
  void PrintSs4(Instruction* instr);
  void PrintSs5(Instruction* instr);
  void PrintBc(Instruction* instr);
  void PrintCc(Instruction* instr);
  void PrintFunction(Instruction* instr);
  void PrintSecondaryField(Instruction* instr);
  void PrintUImm9(Instruction* instr);
  void PrintSImm9(Instruction* instr);
  void PrintUImm16(Instruction* instr);
  void PrintSImm16(Instruction* instr);
  void PrintXImm16(Instruction* instr);
  void PrintPCImm16(Instruction* instr, int delta_pc, int n_bits);
  void PrintXImm18(Instruction* instr);
  void PrintSImm18(Instruction* instr);
  void PrintXImm19(Instruction* instr);
  void PrintSImm19(Instruction* instr);
  void PrintXImm21(Instruction* instr);
  void PrintSImm21(Instruction* instr);
  void PrintPCImm21(Instruction* instr, int delta_pc, int n_bits);
  void PrintXImm26(Instruction* instr);
  void PrintSImm26(Instruction* instr);
  void PrintPCImm26(Instruction* instr, int delta_pc, int n_bits);
  void PrintPCImm26(Instruction* instr);
  void PrintCode(Instruction* instr);    // For break and trap instructions.
  void PrintFormat(Instruction* instr);  // For floating format postfix.
  void PrintBp2(Instruction* instr);
  void PrintBp3(Instruction* instr);
  void PrintMsaDataFormat(Instruction* instr);
  void PrintMsaXImm8(Instruction* instr);
  void PrintMsaImm8(Instruction* instr);
  void PrintMsaImm5(Instruction* instr);
  void PrintMsaSImm5(Instruction* instr);
  void PrintMsaSImm10(Instruction* instr, bool is_mi10 = false);
  void PrintMsaImmBit(Instruction* instr);
  void PrintMsaImmElm(Instruction* instr);
  void PrintMsaCopy(Instruction* instr);
  // Printing of instruction name.
  void PrintInstructionName(Instruction* instr);

  // Handle formatting of instructions and their options.
  int FormatRegister(Instruction* instr, const char* option);
  int FormatFPURegister(Instruction* instr, const char* option);
  int FormatMSARegister(Instruction* instr, const char* option);
  int FormatOption(Instruction* instr, const char* option);
  void Format(Instruction* instr, const char* format);
  void Unknown(Instruction* instr);
  int DecodeBreakInstr(Instruction* instr);

  // Each of these functions decodes one particular instruction type.
  bool DecodeTypeRegisterRsType(Instruction* instr);
  void DecodeTypeRegisterSRsType(Instruction* instr);
  void DecodeTypeRegisterDRsType(Instruction* instr);
  void DecodeTypeRegisterLRsType(Instruction* instr);
  void DecodeTypeRegisterWRsType(Instruction* instr);
  void DecodeTypeRegisterSPECIAL(Instruction* instr);
  void DecodeTypeRegisterSPECIAL2(Instruction* instr);
  void DecodeTypeRegisterSPECIAL3(Instruction* instr);
  void DecodeTypeRegisterCOP1(Instruction* instr);
  void DecodeTypeRegisterCOP1X(Instruction* instr);
  int DecodeTypeRegister(Instruction* instr);

  void DecodeTypeImmediateCOP1(Instruction* instr);
  void DecodeTypeImmediateREGIMM(Instruction* instr);
  void DecodeTypeImmediateSPECIAL3(Instruction* instr);
  void DecodeTypeImmediate(Instruction* instr);

  void DecodeTypeJump(Instruction* instr);

  void DecodeTypeMsaI8(Instruction* instr);
  void DecodeTypeMsaI5(Instruction* instr);
  void DecodeTypeMsaI10(Instruction* instr);
  void DecodeTypeMsaELM(Instruction* instr);
  void DecodeTypeMsaBIT(Instruction* instr);
  void DecodeTypeMsaMI10(Instruction* instr);
  void DecodeTypeMsa3R(Instruction* instr);
  void DecodeTypeMsa3RF(Instruction* instr);
  void DecodeTypeMsaVec(Instruction* instr);
  void DecodeTypeMsa2R(Instruction* instr);
  void DecodeTypeMsa2RF(Instruction* instr);

  const disasm::NameConverter& converter_;
  v8::base::Vector<char> out_buffer_;
  int out_buffer_pos_;
};

// Support for assertions in the Decoder formatting functions.
#define STRING_STARTS_WITH(string, compare_string) \
  (strncmp(string, compare_string, strlen(compare_string)) == 0)

// Append the ch to the output buffer.
void Decoder::PrintChar(const char ch) { out_buffer_[out_buffer_pos_++] = ch; }

// Append the str to the output buffer.
void Decoder::Print(const char* str) {
  char cur = *str++;
  while (cur != '\0' && (out_buffer_pos_ < (out_buffer_.length() - 1))) {
    PrintChar(cur);
    cur = *str++;
  }
  out_buffer_[out_buffer_pos_] = 0;
}

// Print the register name according to the active name converter.
void Decoder::PrintRegister(int reg) {
  Print(converter_.NameOfCPURegister(reg));
}

void Decoder::PrintRs(Instruction* instr) {
  int reg = instr->RsValue();
  PrintRegister(reg);
}

void Decoder::PrintRt(Instruction* instr) {
  int reg = instr->RtValue();
  PrintRegister(reg);
}

void Decoder::PrintRd(Instruction* instr) {
  int reg = instr->RdValue();
  PrintRegister(reg);
}

// Print the FPUregister name according to the active name converter.
void Decoder::PrintFPURegister(int freg) {
  Print(converter_.NameOfXMMRegister(freg));
}

void Decoder::PrintMSARegister(int wreg) { Print(MSARegisters::Name(wreg)); }

void Decoder::PrintFPUStatusRegister(int freg) {
  switch (freg) {
    case kFCSRRegister:
      Print("FCSR");
      break;
    default:
      Print(converter_.NameOfXMMRegister(freg));
  }
}

void Decoder::PrintMSAControlRegister(int creg) {
  switch (creg) {
    case kMSAIRRegister:
      Print("MSAIR");
      break;
    case kMSACSRRegister:
      Print("MSACSR");
      break;
    default:
      Print("no_msacreg");
  }
}

void Decoder::PrintFs(Instruction* instr) {
  int freg = instr->RsValue();
  PrintFPURegister(freg);
}

void Decoder::PrintFt(Instruction* instr) {
  int freg = instr->RtValue();
  PrintFPURegister(freg);
}

void Decoder::PrintFd(Instruction* instr) {
  int freg = instr->RdValue();
  PrintFPURegister(freg);
}

// Print the integer value of the sa field.
void Decoder::PrintSa(Instruction* instr) {
  int sa = instr->SaValue();
  out_buffer_pos_ += base::SNPrintF(out_buffer_ + out_buffer_pos_, "%d", sa);
}

// Print the integer value of the sa field of a lsa instruction.
void Decoder::PrintLsaSa(Instruction* instr) {
  int sa = instr->LsaSaValue() + 1;
  out_buffer_pos_ += base::SNPrintF(out_buffer_ + out_buffer_pos_, "%d", sa);
}

// Print the integer value of the rd field, when it is not used as reg.
void Decoder::PrintSd(Instruction* instr) {
  int sd = instr->RdValue();
  out_buffer_pos_ += base::SNPrintF(out_buffer_ + out_buffer_pos_, "%d", sd);
}

// Print the integer value of ext/dext/dextu size from the msbd field.
void Decoder::PrintSs1(Instruction* instr) {
  int msbd = instr->RdValue();
  out_buffer_pos_ +=
      base::SNPrintF(out_buffer_ + out_buffer_pos_, "%d", msbd + 1);
}

// Print the integer value of ins/dins/dinsu size from the msb and lsb fields
// (for dinsu it is msbminus32 and lsbminus32 fields).
void Decoder::PrintSs2(Instruction* instr) {
  int msb = instr->RdValue();
  int lsb = instr->SaValue();
  out_buffer_pos_ +=
      base::SNPrintF(out_buffer_ + out_buffer_pos_, "%d", msb - lsb + 1);
}

// Print the integer value of dextm size from the msbdminus32 field.
void Decoder::PrintSs3(Instruction* instr) {
  int msbdminus32 = instr->RdValue();
  out_buffer_pos_ +=
      base::SNPrintF(out_buffer_ + out_buffer_pos_, "%d", msbdminus32 + 32 + 1);
}

// Print the integer value of dinsm size from the msbminus32 and lsb fields.
void Decoder::PrintSs4(Instruction* instr) {
  int msbminus32 = instr->RdValue();
  int lsb = instr->SaValue();
  out_buffer_pos_ += base::SNPrintF(out_buffer_ + out_buffer_pos_, "%d",
                                    msbminus32 + 32 - lsb + 1);
}

// Print the integer value of dextu/dinsu pos from the lsbminus32 field.
void Decoder::PrintSs5(Instruction* instr) {
  int lsbminus32 = instr->SaValue();
  out_buffer_pos_ +=
      base::SNPrintF(out_buffer_ + out_buffer_pos_, "%d", lsbminus32 + 32);
}

// Print the integer value of the cc field for the bc1t/f instructions.
void Decoder::PrintBc(Instruction* instr) {
  int cc = instr->FBccValue();
  out_buffer_pos_ += base::SNPrintF(out_buffer_ + out_buffer_pos_, "%d", cc);
}

// Print the integer value of the cc field for the FP compare instructions.
void Decoder::PrintCc(Instruction* instr) {
  int cc = instr->FCccValue();
  out_buffer_pos_ +=
      base::SNPrintF(out_buffer_ + out_buffer_pos_, "cc(%d)", cc);
}

// Print 9-bit unsigned immediate value.
void Decoder::PrintUImm9(Instruction* instr) {
  int32_t imm = instr->Imm9Value();
  out_buffer_pos_ += base::SNPrintF(out_buffer_ + out_buffer_pos_, "%u", imm);
}

// Print 9-bit signed immediate value.
void Decoder::PrintSImm9(Instruction* instr) {
  int32_t imm = ((instr->Imm9Value()) << 23) >> 23;
  out_buffer_pos_ += base::SNPrintF(out_buffer_ + out_buffer_pos_, "%d", imm);
}

// Print 16-bit unsigned immediate value.
void Decoder::PrintUImm16(Instruction* instr) {
  int32_t imm = instr->Imm16Value();
  out_buffer_pos_ += base::SNPrintF(out_buffer_ + out_buffer_pos_, "%u", imm);
}

// Print 16-bit signed immediate value.
void Decoder::PrintSImm16(Instruction* instr) {
  int32_t imm =
      ((instr->Imm16Value()) << (32 - kImm16Bits)) >> (32 - kImm16Bits);
  out_buffer_pos_ += base::SNPrintF(out_buffer_ + out_buffer_pos_, "%d", imm);
}

// Print 16-bit hexa immediate value.
void Decoder::PrintXImm16(Instruction* instr) {
  int32_t imm = instr->Imm16Value();
  out_buffer_pos_ += base::SNPrintF(out_buffer_ + out_buffer_pos_, "0x%x", imm);
}

// Print absoulte address for 16-bit offset or immediate value.
// The absolute address is calculated according following expression:
//      PC + delta_pc + (offset << n_bits)
void Decoder::PrintPCImm16(Instruction* instr, int delta_pc, int n_bits) {
  int16_t offset = instr->Imm16Value();
  out_buffer_pos_ += base::SNPrintF(
      out_buffer_ + out_buffer_pos_, "%s",
      converter_.NameOfAddress(reinterpret_cast<uint8_t*>(instr) + delta_pc +
                               (offset << n_bits)));
}

// Print 18-bit signed immediate value.
void Decoder::PrintSImm18(Instruction* instr) {
  int32_t imm =
      ((instr->Imm18Value()) << (32 - kImm18Bits)) >> (32 - kImm18Bits);
  out_buffer_pos_ += base::SNPrintF(out_buffer_ + out_buffer_pos_, "%d", imm);
}

// Print 18-bit hexa immediate value.
void Decoder::PrintXImm18(Instruction* instr) {
  int32_t imm = instr->Imm18Value();
  out_buffer_pos_ += base::SNPrintF(out_buffer_ + out_buffer_pos_, "0x%x", imm);
}

// Print 19-bit hexa immediate value.
void Decoder::PrintXImm19(Instruction* instr) {
  int32_t imm = instr->Imm19Value();
  out_buffer_pos_ += base::SNPrintF(out_buffer_ + out_buffer_pos_, "0x%x", imm);
}

// Print 19-bit signed immediate value.
void Decoder::PrintSImm19(Instruction* instr) {
  int32_t imm19 = instr->Imm19Value();
  // set sign
  imm19 <<= (32 - kImm19Bits);
  imm19 >>= (32 - kImm19Bits);
  out_buffer_pos_ += base::SNPrintF(out_buffer_ + out_buffer_pos_, "%d", imm19);
}

// Print 21-bit immediate value.
void Decoder::PrintXImm21(Instruction* instr) {
  uint32_t imm = instr->Imm21Value();
  out_buffer_pos_ += base::SNPrintF(out_buffer_ + out_buffer_pos_, "0x%x", imm);
}

// Print 21-bit signed immediate value.
void Decoder::PrintSImm21(Instruction* instr) {
  int32_t imm21 = instr->Imm21Value();
  // set sign
  imm21 <<= (32 - kImm21Bits);
  imm21 >>= (32 - kImm21Bits);
  out_buffer_pos_ += base::SNPrintF(out_buffer_ + out_buffer_pos_, "%d", imm21);
}

// Print absoulte address for 21-bit offset or immediate value.
// The absolute address is calculated according following expression:
//      PC + delta_pc + (offset << n_bits)
void Decoder::PrintPCImm21(Instruction* instr, int delta_pc, int n_bits) {
  int32_t imm21 = instr->Imm21Value();
  // set sign
  imm21 <<= (32 - kImm21Bits);
  imm21 >>= (32 - kImm21Bits);
  out_buffer_pos_ += base::SNPrintF(
      out_buffer_ + out_buffer_pos_, "%s",
      converter_.NameOfAddress(reinterpret_cast<uint8_t*>(instr) + delta_pc +
                               (imm21 << n_bits)));
}

// Print 26-bit hex immediate value.
void Decoder::PrintXImm26(Instruction* instr) {
  uint64_t target = static_cast<uint64_t>(instr->Imm26Value())
                    << kImmFieldShift;
  target = (reinterpret_cast<uint64_t>(instr) & ~0xFFFFFFF) | target;
  out_buffer_pos_ +=
      base::SNPrintF(out_buffer_ + out_buffer_pos_, "0x%" PRIx64, target);
}

// Print 26-bit signed immediate value.
void Decoder::PrintSImm26(Instruction* instr) {
  int32_t imm26 = instr->Imm26Value();
  // set sign
  imm26 <<= (32 - kImm26Bits);
  imm26 >>= (32 - kImm26Bits);
  out_buffer_pos_ += base::SNPrintF(out_buffer_ + out_buffer_pos_, "%d", imm26);
}

// Print absoulte address for 26-bit offset or immediate value.
// The absolute address is calculated according following expression:
//      PC + delta_pc + (offset << n_bits)
void Decoder::PrintPCImm26(Instruction* instr, int delta_pc, int n_bits) {
  int32_t imm26 = instr->Imm26Value();
  // set sign
  imm26 <<= (32 - kImm26Bits);
  imm26 >>= (32 - kImm26Bits);
  out_buffer_pos_ += base::SNPrintF(
      out_buffer_ + out_buffer_pos_, "%s",
      converter_.NameOfAddress(reinterpret_cast<uint8_t*>(instr) + delta_pc +
                               (imm26 << n_bits)));
}

// Print absoulte address for 26-bit offset or immediate value.
// The absolute address is calculated according following expression:
//      PC[GPRLEN-1 .. 28] || instr_index26 || 00
void Decoder::PrintPCImm26(Instruction* instr) {
  int32_t imm26 = instr->Imm26Value();
  uint64_t pc_mask = ~0xFFFFFFF;
  uint64_t pc = ((uint64_t)(instr + 1) & pc_mask) | (imm26 << 2);
  out_buffer_pos_ += base::SNPrintF(
      out_buffer_ + out_buffer_pos_, "%s",
      converter_.NameOfAddress((reinterpret_cast<uint8_t*>(pc))));
}

void Decoder::PrintBp2(Instruction* instr) {
  int bp2 = instr->Bp2Value();
  out_buffer_pos_ += base::SNPrintF(out_buffer_ + out_buffer_pos_, "%d", bp2);
}

void Decoder::PrintBp3(Instruction* instr) {
  int bp3 = instr->Bp3Value();
  out_buffer_pos_ += base::SNPrintF(out_buffer_ + out_buffer_pos_, "%d", bp3);
}

// Print 26-bit immediate value.
void Decoder::PrintCode(Instruction* instr) {
  if (instr->OpcodeFieldRaw() != SPECIAL)
    return;  // Not a break or trap instruction.
  switch (instr->FunctionFieldRaw()) {
    case BREAK: {
      int32_t code = instr->Bits(25, 6);
      out_buffer_pos_ += base::SNPrintF(out_buffer_ + out_buffer_pos_,
                                        "0x%05x (%d)", code, code);
      break;
    }
    case TGE:
    case TGEU:
    case TLT:
    case TLTU:
    case TEQ:
    case TNE: {
      int32_t code = instr->Bits(15, 6);
      out_buffer_pos_ +=
          base::SNPrintF(out_buffer_ + out_buffer_pos_, "0x%03x", code);
      break;
    }
    default:  // Not a break or trap instruction.
      break;
  }
}

void Decoder::PrintMsaXImm8(Instruction* instr) {
  int32_t imm = instr->MsaImm8Value();
  out_buffer_pos_ += base::SNPrintF(out_buffer_ + out_buffer_pos_, "0x%x", imm);
}

void Decoder::PrintMsaImm8(Instruction* instr) {
  int32_t imm = instr->MsaImm8Value();
  out_buffer_pos_ += base::SNPrintF(out_buffer_ + out_buffer_pos_, "%u", imm);
}

void Decoder::PrintMsaImm5(Instruction* instr) {
  int32_t imm = instr->MsaImm5Value();
  out_buffer_pos_ += base::SNPrintF(out_buffer_ + out_buffer_pos_, "%u", imm);
}

void Decoder::PrintMsaSImm5(Instruction* instr) {
  int32_t imm = instr->MsaImm5Value();
  imm <<= (32 - kMsaImm5Bits);
  imm >>= (32 - kMsaImm5Bits);
  out_buffer_pos_ += base::SNPrintF(out_buffer_ + out_buffer_pos_, "%d", imm);
}

void Decoder::PrintMsaSImm10(Instruction* instr, bool is_mi10) {
  int32_t imm = is_mi10 ? instr->MsaImmMI10Value() : instr->MsaImm10Value();
  imm <<= (32 - kMsaImm10Bits);
  imm >>= (32 - kMsaImm10Bits);
  out_buffer_pos_ += base::SNPrintF(out_buffer_ + out_buffer_pos_, "%d", imm);
}

void Decoder::PrintMsaImmBit(Instruction* instr) {
  int32_t m = instr->MsaBitMValue();
  out_buffer_pos_ += base::SNPrintF(out_buffer_ + out_buffer_pos_, "%u", m);
}

void Decoder::PrintMsaImmElm(Instruction* instr) {
  int32_t n = instr->MsaElmNValue();
  out_buffer_pos_ += base::SNPrintF(out_buffer_ + out_buffer_pos_, "%u", n);
}

void Decoder::PrintMsaCopy(Instruction* instr) {
  int32_t rd = instr->WdValue();
  int32_t ws = instr->WsValue();
  int32_t n = instr->MsaElmNValue();
  out_buffer_pos_ += base::SNPrintF(out_buffer_ + out_buffer_pos_, "%s, %s[%u]",
                                    converter_.NameOfCPURegister(rd),
                                    MSARegisters::Name(ws), n);
}

void Decoder::PrintFormat(Instruction* instr) {
  char formatLetter = ' ';
  switch (instr->RsFieldRaw()) {
    case S:
      formatLetter = 's';
      break;
    case D:
      formatLetter = 'd';
      break;
    case W:
      formatLetter = 'w';
      break;
    case L:
      formatLetter = 'l';
      break;
    default:
      UNREACHABLE();
  }
  PrintChar(formatLetter);
}

void Decoder::PrintMsaDataFormat(Instruction* instr) {
  DCHECK(instr->IsMSAInstr());
  char df = ' ';
  if (instr->IsMSABranchInstr()) {
    switch (instr->RsFieldRaw()) {
      case BZ_V:
      case BNZ_V:
        df = 'v';
        break;
      case BZ_B:
      case BNZ_B:
        df = 'b';
        break;
      case BZ_H:
      case BNZ_H:
        df = 'h';
        break;
      case BZ_W:
      case BNZ_W:
        df = 'w';
        break;
      case BZ_D:
      case BNZ_D:
        df = 'd';
        break;
      default:
        UNREACHABLE();
    }
  } else {
    char DF[] = {'b', 'h', 'w', 'd'};
    switch (instr->MSAMinorOpcodeField()) {
      case kMsaMinorI5:
      case kMsaMinorI10:
      case kMsaMinor3R:
        df = DF[instr->Bits(22, 21)];
        break;
      case kMsaMinorMI10:
        df = DF[instr->Bits(1, 0)];
        break;
      case kMsaMinorBIT:
        df = DF[instr->MsaBitDf()];
        break;
      case kMsaMinorELM:
        df = DF[instr->MsaElmDf()];
        break;
      case kMsaMinor3RF: {
        uint32_t opcode = instr->InstructionBits() & kMsa3RFMask;
        switch (opcode) {
          case FEXDO:
          case FTQ:
          case MUL_Q:
          case MADD_Q:
          case MSUB_Q:
          case MULR_Q:
          case MADDR_Q:
          case MSUBR_Q:
            df = DF[1 + instr->Bit(21)];
            break;
          default:
            df = DF[2 + instr->Bit(21)];
            break;
        }
      } break;
      case kMsaMinor2R:
        df = DF[instr->Bits(17, 16)];
        break;
      case kMsaMinor2RF:
        df = DF[2 + instr->Bit(16)];
        break;
      default:
        UNREACHABLE();
    }
  }

  PrintChar(df);
}

// Printing of instruction name.
void Decoder::PrintInstructionName(Instruction* instr) {}

// Handle all register based formatting in this function to reduce the
// complexity of FormatOption.
int Decoder::FormatRegister(Instruction* instr, const char* format) {
  DCHECK_EQ(format[0], 'r');
  if (format[1] == 's') {  // 'rs: Rs register.
    int reg = instr->RsValue();
    PrintRegister(reg);
    return 2;
  } else if (format[1] == 't') {  // 'rt: rt register.
    int reg = instr->RtValue();
    PrintRegister(reg);
    return 2;
  } else if (format[1] == 'd') {  // 'rd: rd register.
    int reg = instr->RdValue();
    PrintRegister(reg);
    return 2;
  }
  UNREACHABLE();
}

// Handle all FPUregister based formatting in this function to reduce the
// complexity of FormatOption.
int Decoder::FormatFPURegister(Instruction* instr, const char* format) {
  DCHECK_EQ(format[0], 'f');
  if ((CTC1 == instr->RsFieldRaw()) || (CFC1 == instr->RsFieldRaw())) {
    if (format[1] == 's') {  // 'fs: fs register.
      int reg = instr->FsValue();
      PrintFPUStatusRegister(reg);
      return 2;
    } else if (format[1] == 't') {  // 'ft: ft register.
      int reg = instr->FtValue();
      PrintFPUStatusRegister(reg);
      return 2;
    } else if (format[1] == 'd') {  // 'fd: fd register.
      int reg = instr->FdValue();
      PrintFPUStatusRegister(reg);
      return 2;
    } else if (format[1] == 'r') {  // 'fr: fr register.
      int reg = instr->FrValue();
      PrintFPUStatusRegister(reg);
      return 2;
    }
  } else {
    if (format[1] == 's') {  // 'fs: fs register.
      int reg = instr->FsValue();
      PrintFPURegister(reg);
      return 2;
    } else if (format[1] == 't') {  // 'ft: ft register.
      int reg = instr->FtValue();
      PrintFPURegister(reg);
      return 2;
    } else if (format[1] == 'd') {  // 'fd: fd register.
      int reg = instr->FdValue();
      PrintFPURegister(reg);
      return 2;
    } else if (format[1] == 'r') {  // 'fr: fr register.
      int reg = instr->FrValue();
      PrintFPURegister(reg);
      return 2;
    }
  }
  UNREACHABLE();
}

// Handle all MSARegister based formatting in this function to reduce the
// complexity of FormatOption.
int Decoder::FormatMSARegister(Instruction* instr, const char* format) {
  DCHECK_EQ(format[0], 'w');
  if (format[1] == 's') {
    int reg = instr->WsValue();
    PrintMSARegister(reg);
    return 2;
  } else if (format[1] == 't') {
    int reg = instr->WtValue();
    PrintMSARegister(reg);
    return 2;
  } else if (format[1] == 'd') {
    int reg = instr->WdValue();
    PrintMSARegister(reg);
    return 2;
  }

  UNREACHABLE();
}

// FormatOption takes a formatting string and interprets it based on
// the current instructions. The format string points to the first
// character of the option string (the option escape has already been
// consumed by the caller.)  FormatOption returns the number of
// characters that were consumed from the formatting string.
int Decoder::FormatOption(Instruction* instr, const char* format) {
  switch (format[0]) {
    case 'c': {  // 'code for break or trap instructions.
      DCHECK(STRING_STARTS_WITH(format, "code"));
      PrintCode(instr);
      return 4;
    }
    case 'i': {  // 'imm16u or 'imm26.
      if (format[3] == '1') {
        if (format[4] == '6') {
          DCHECK(STRING_STARTS_WITH(format, "imm16"));
          switch (format[5]) {
            case 's':
              DCHECK(STRING_STARTS_WITH(format, "imm16s"));
              PrintSImm16(instr);
              break;
            case 'u':
              DCHECK(STRING_STARTS_WITH(format, "imm16u"));
              PrintSImm16(instr);
              break;
            case 'x':
              DCHECK(STRING_STARTS_WITH(format, "imm16x"));
              PrintXImm16(instr);
              break;
            case 'p': {  // The PC relative address.
              DCHECK(STRING_STARTS_WITH(format, "imm16p"));
              int delta_pc = 0;
              int n_bits = 0;
              switch (format[6]) {
                case '4': {
                  DCHECK(STRING_STARTS_WITH(format, "imm16p4"));
                  delta_pc = 4;
                  switch (format[8]) {
                    case '2':
                      DCHECK(STRING_STARTS_WITH(format, "imm16p4s2"));
                      n_bits = 2;
                      PrintPCImm16(instr, delta_pc, n_bits);
                      return 9;
                  }
                }
              }
            }
          }
          return 6;
        } else if (format[4] == '8') {
          DCHECK(STRING_STARTS_WITH(format, "imm18"));
          switch (format[5]) {
            case 's':
              DCHECK(STRING_STARTS_WITH(format, "imm18s"));
              PrintSImm18(instr);
              break;
            case 'x':
              DCHECK(STRING_STARTS_WITH(format, "imm18x"));
              PrintXImm18(instr);
              break;
          }
          return 6;
        } else if (format[4] == '9') {
          DCHECK(STRING_STARTS_WITH(format, "imm19"));
          switch (format[5]) {
            case 's':
              DCHECK(STRING_STARTS_WITH(format, "imm19s"));
              PrintSImm19(instr);
              break;
            case 'x':
              DCHECK(STRING_STARTS_WITH(format, "imm19x"));
              PrintXImm19(instr);
              break;
          }
          return 6;
        } else if (format[4] == '0' && format[5] == 's') {
          DCHECK(STRING_STARTS_WITH(format, "imm10s"));
          if (format[6] == '1') {
            DCHECK(STRING_STARTS_WITH(format, "imm10s1"));
            PrintMsaSImm10(instr, false);
          } else if (format[6] == '2') {
            DCHECK(STRING_STARTS_WITH(format, "imm10s2"));
            PrintMsaSImm10(instr, true);
          }
          return 7;
        }
      } else if (format[3] == '2' && format[4] == '1') {
        DCHECK(STRING_STARTS_WITH(format, "imm21"));
        switch (format[5]) {
          case 's':
            DCHECK(STRING_STARTS_WITH(format, "imm21s"));
            PrintSImm21(instr);
            break;
          case 'x':
            DCHECK(STRING_STARTS_WITH(format, "imm21x"));
            PrintXImm21(instr);
            break;
          case 'p': {  // The PC relative address.
            DCHECK(STRING_STARTS_WITH(format, "imm21p"));
            int delta_pc = 0;
            int n_bits = 0;
            switch (format[6]) {
              case '4': {
                DCHECK(STRING_STARTS_WITH(format, "imm21p4"));
                delta_pc = 4;
                switch (format[8]) {
                  case '2':
                    DCHECK(STRING_STARTS_WITH(format, "imm21p4s2"));
                    n_bits = 2;
                    PrintPCImm21(instr, delta_pc, n_bits);
                    return 9;
                }
              }
            }
          }
        }
        return 6;
      } else if (format[3] == '2' && format[4] == '6') {
        DCHECK(STRING_STARTS_WITH(format, "imm26"));
        switch (format[5]) {
          case 's':
            DCHECK(STRING_STARTS_WITH(format, "imm26s"));
            PrintSImm26(instr);
            break;
          case 'x':
            DCHECK(STRING_STARTS_WITH(format, "imm26x"));
            PrintXImm26(instr);
            break;
          case 'p': {  // The PC relative address.
            DCHECK(STRING_STARTS_WITH(format, "imm26p"));
            int delta_pc = 0;
            int n_bits = 0;
            switch (format[6]) {
              case '4': {
                DCHECK(STRING_STARTS_WITH(format, "imm26p4"));
                delta_pc = 4;
                switch (format[8]) {
                  case '2':
                    DCHECK(STRING_STARTS_WITH(format, "imm26p4s2"));
                    n_bits = 2;
                    PrintPCImm26(instr, delta_pc, n_bits);
                    return 9;
                }
              }
            }
          }
          case 'j': {  // Absolute address for jump instructions.
            DCHECK(STRING_STARTS_WITH(format, "imm26j"));
            PrintPCImm26(instr);
            break;
          }
        }
        return 6;
      } else if (format[3] == '5') {
        DCHECK(STRING_STARTS_WITH(format, "imm5"));
        if (format[4] == 'u') {
          DCHECK(STRING_STARTS_WITH(format, "imm5u"));
          PrintMsaImm5(instr);
        } else if (format[4] == 's') {
          DCHECK(STRING_STARTS_WITH(format, "imm5s"));
          PrintMsaSImm5(instr);
        }
        return 5;
      } else if (format[3] == '8') {
        DCHECK(STRING_STARTS_WITH(format, "imm8"));
        PrintMsaImm8(instr);
        return 4;
      } else if (format[3] == '9') {
        DCHECK(STRING_STARTS_WITH(format, "imm9"));
        if (format[4] == 'u') {
          DCHECK(STRING_STARTS_WITH(format, "imm9u"));
          PrintUImm9(instr);
        } else if (format[4] == 's') {
          DCHECK(STRING_STARTS_WITH(format, "imm9s"));
          PrintSImm9(instr);
        }
        return 5;
      } else if (format[3] == 'b') {
        DCHECK(STRING_STARTS_WITH(format, "immb"));
        PrintMsaImmBit(instr);
        return 4;
      } else if (format[3] == 'e') {
        DCHECK(STRING_STARTS_WITH(format, "imme"));
        PrintMsaImmElm(instr);
        return 4;
      }
      UNREACHABLE();
    }
    case 'r': {  // 'r: registers.
      return FormatRegister(instr, format);
    }
    case 'f': {  // 'f: FPUregisters.
      return FormatFPURegister(instr, format);
    }
    case 'w': {  // 'w: MSA Register
      return FormatMSARegister(instr, format);
    }
    case 's': {  // 'sa.
      switch (format[1]) {
        case 'a':
          if (format[2] == '2') {
            DCHECK(STRING_STARTS_WITH(format, "sa2"));  // 'sa2
            PrintLsaSa(instr);
            return 3;
          } else {
            DCHECK(STRING_STARTS_WITH(format, "sa"));
            PrintSa(instr);
            return 2;
          }
        case 'd': {
          DCHECK(STRING_STARTS_WITH(format, "sd"));
          PrintSd(instr);
          return 2;
        }
        case 's': {
          if (format[2] == '1') {
            DCHECK(STRING_STARTS_WITH(format, "ss1"));  // ext, dext, dextu size
            PrintSs1(instr);
          } else if (format[2] == '2') {
            DCHECK(STRING_STARTS_WITH(format, "ss2"));  // ins, dins, dinsu size
            PrintSs2(instr);
          } else if (format[2] == '3') {
            DCHECK(STRING_STARTS_WITH(format, "ss3"));  // dextm size
            PrintSs3(instr);
          } else if (format[2] == '4') {
            DCHECK(STRING_STARTS_WITH(format, "ss4"));  // dinsm size
            PrintSs4(instr);
          } else {
            DCHECK(STRING_STARTS_WITH(format, "ss5"));  // dextu, dinsu pos
            PrintSs5(instr);
          }
          return 3;
        }
      }
    }
    case 'b': {
      switch (format[1]) {
        case 'c': {  // 'bc - Special for bc1 cc field.
          DCHECK(STRING_STARTS_WITH(format, "bc"));
          PrintBc(instr);
          return 2;
        }
        case 'p': {
          switch (format[2]) {
            case '2': {  // 'bp2
              DCHECK(STRING_STARTS_WITH(format, "bp2"));
              PrintBp2(instr);
              return 3;
            }
            case '3': {  // 'bp3
              DCHECK(STRING_STARTS_WITH(format, "bp3"));
              PrintBp3(instr);
              return 3;
            }
          }
        }
      }
    }
    case 'C': {  // 'Cc - Special for c.xx.d cc field.
      DCHECK(STRING_STARTS_WITH(format, "Cc"));
      PrintCc(instr);
      return 2;
    }
    case 't':
      if (instr->IsMSAInstr()) {
        PrintMsaDataFormat(instr);
      } else {
        PrintFormat(instr);
      }
      return 1;
  }
  UNREACHABLE();
}

// Format takes a formatting string for a whole instruction and prints it into
// the output buffer. All escaped options are handed to FormatOption to be
// parsed further.
void Decoder::Format(Instruction* instr, const char* format) {
  char cur = *format++;
  while ((cur != 0) && (out_buffer_pos_ < (out_buffer_.length() - 1))) {
    if (cur == '\'') {  // Single quote is used as the formatting escape.
      format += FormatOption(instr, format);
    } else {
      out_buffer_[out_buffer_pos_++] = cur;
    }
    cur = *format++;
  }
  out_buffer_[out_buffer_pos_] = '\0';
}

// For currently unimplemented decodings the disassembler calls Unknown(instr)
// which will just print "unknown" of the instruction bits.
void Decoder::Unknown(Instruction* instr) { Format(instr, "unknown"); }

int Decoder::DecodeBreakInstr(Instruction* instr) {
  // This is already known to be BREAK instr, just extract the code.
  if (instr->Bits(25, 6) == static_cast<int>(kMaxStopCode)) {
    // This is stop(msg).
    Format(instr, "break, code: 'code");
    out_buffer_pos_ += base::SNPrintF(
        out_buffer_ + out_buffer_pos_, "\n%p       %08" PRIx64,
        static_cast<void*>(reinterpret_cast<int32_t*>(instr + kInstrSize)),
        reinterpret_cast<uint64_t>(
            *reinterpret_cast<char**>(instr + kInstrSize)));
    // Size 3: the break_ instr, plus embedded 64-bit char pointer.
    return 3 * kInstrSize;
  } else {
    Format(instr, "break, code: 'code");
    return kInstrSize;
  }
}

bool Decoder::DecodeTypeRegisterRsType(Instruction* instr) {
  switch (instr->FunctionFieldRaw()) {
    case RINT:
      Format(instr, "rint.'t    'fd, 'fs");
      break;
    case SEL:
      Format(instr, "sel.'t      'fd, 'fs, 'ft");
      break;
    case SELEQZ_C:
      Format(instr, "seleqz.'t    'fd, 'fs, 'ft");
      break;
    case SELNEZ_C:
      Format(instr, "selnez.'t    'fd, 'fs, 'ft");
      break;
    case MOVZ_C:
      Format(instr, "movz.'t    'fd, 'fs, 'rt");
      break;
    case MOVN_C:
      Format(instr, "movn.'t    'fd, 'fs, 'rt");
      break;
    case MOVF:
      if (instr->Bit(16)) {
        Format(instr, "movt.'t    'fd, 'fs, 'Cc");
      } else {
        Format(instr, "movf.'t    'fd, 'fs, 'Cc");
      }
      break;
    case MIN:
      Format(instr, "min.'t    'fd, 'fs, 'ft");
      break;
    case MAX:
      Format(instr, "max.'t    'fd, 'fs, 'ft");
      break;
    case MINA:
      Format(instr, "mina.'t   'fd, 'fs, 'ft");
      break;
    case MAXA:
      Format(instr, "maxa.'t   'fd, 'fs, 'ft");
      break;
    case ADD_D:
      Format(instr, "add.'t   'fd, 'fs, 'ft");
      break;
    case SUB_D:
      Format(instr, "sub.'t   'fd, 'fs, 'ft");
      break;
    case MUL_D:
      Format(instr, "mul.'t   'fd, 'fs, 'ft");
      break;
    case DIV_D:
      Format(instr, "div.'t   'fd, 'fs, 'ft");
      break;
    case ABS_D:
      Format(instr, "abs.'t   'fd, 'fs");
      break;
    case MOV_D:
      Format(instr, "mov.'t   'fd, 'fs");
      break;
    case NEG_D:
      Format(instr, "neg.'t   'fd, 'fs");
      break;
    case SQRT_D:
      Format(instr, "sqrt.'t  'fd, 'fs");
      break;
    case RECIP_D:
      Format(instr, "recip.'t  'fd, 'fs");
      break;
    case RSQRT_D:
      Format(instr, "rsqrt.'t  'fd, 'fs");
      break;
    case CVT_W_D:
      Format(instr, "cvt.w.'t 'fd, 'fs");
      break;
    case CVT_L_D:
      Format(instr, "cvt.l.'t 'fd, 'fs");
      break;
    case TRUNC_W_D:
      Format(instr, "trunc.w.'t 'fd, 'fs");
      break;
    case TRUNC_L_D:
      Format(instr, "trunc.l.'t 'fd, 'fs");
      break;
    case ROUND_W_D:
      Format(instr, "round.w.'t 'fd, 'fs");
      break;
    case ROUND_L_D:
      Format(instr, "round.l.'t 'fd, 'fs");
      break;
    case FLOOR_W_D:
      Format(instr, "floor.w.'t 'fd, 'fs");
      break;
    case FLOOR_L_D:
      Format(instr, "floor.l.'t 'fd, 'fs");
      break;
    case CEIL_W_D:
      Format(instr, "ceil.w.'t 'fd, 'fs");
      break;
    case CEIL_L_D:
      Format(instr, "ceil.l.'t 'fd, 'fs");
      break;
    case CLASS_D:
      Format(instr, "class.'t 'fd, 'fs");
      break;
    case CVT_S_D:
      Format(instr, "cvt.s.'t 'fd, 'fs");
      break;
    case C_F_D:
      Format(instr, "c.f.'t   'fs, 'ft, 'Cc");
      break;
    case C_UN_D:
      Format(instr, "c.un.'t  'fs, 'ft, 'Cc");
      break;
    case C_EQ_D:
      Format(instr, "c.eq.'t  'fs, 'ft, 'Cc");
      break;
    case C_UEQ_D:
      Format(instr, "c.ueq.'t 'fs, 'ft, 'Cc");
      break;
    case C_OLT_D:
      Format(instr, "c.olt.'t 'fs, 'ft, 'Cc");
      break;
    case C_ULT_D:
      Format(instr, "c.ult.'t 'fs, 'ft, 'Cc");
      break;
    case C_OLE_D:
      Format(instr, "c.ole.'t 'fs, 'ft, 'Cc");
      break;
    case C_ULE_D:
      Format(instr, "c.ule.'t 'fs, 'ft, 'Cc");
      break;
    default:
      return false;
  }
  return true;
}

void Decoder::DecodeTypeRegisterSRsType(Instruction* instr) {
  if (!DecodeTypeRegisterRsType(instr)) {
    switch (instr->FunctionFieldRaw()) {
      case CVT_D_S:
        Format(instr, "cvt.d.'t 'fd, 'fs");
        break;
      case MADDF_S:
        Format(instr, "maddf.s  'fd, 'fs, 'ft");
        break;
      case MSUBF_S:
        Format(instr, "msubf.s  'fd, 'fs, 'ft");
        break;
      default:
        Format(instr, "unknown.cop1.'t");
        break;
    }
  }
}

void Decoder::DecodeTypeRegisterDRsType(Instruction* instr) {
  if (!DecodeTypeRegisterRsType(instr)) {
    switch (instr->FunctionFieldRaw()) {
      case MADDF_D:
        Format(instr, "maddf.d  'fd, 'fs, 'ft");
        break;
      case MSUBF_D:
        Format(instr, "msubf.d  'fd, 'fs, 'ft");
        break;
      default:
        Format(instr, "unknown.cop1.'t");
        break;
    }
  }
}

void Decoder::DecodeTypeRegisterLRsType(Instruction* instr) {
  switch (instr->FunctionFieldRaw()) {
    case CVT_D_L:
      Format(instr, "cvt.d.l 'fd, 'fs");
      break;
    case CVT_S_L:
      Format(instr, "cvt.s.l 'fd, 'fs");
      break;
    case CMP_AF:
      Format(instr, "cmp.af.d  'fd,  'fs, 'ft");
      break;
    case CMP_UN:
      Format(instr, "cmp.un.d  'fd,  'fs, 'ft");
      break;
    case CMP_EQ:
      Format(instr, "cmp.eq.d  'fd,  'fs, 'ft");
      break;
    case CMP_UEQ:
      Format(instr, "cmp.ueq.d  'fd,  'fs, 'ft");
      break;
    case CMP_LT:
      Format(instr, "cmp.lt.d  'fd,  'fs, 'ft");
      break;
    case CMP_ULT:
      Format(instr, "cmp.ult.d  'fd,  'fs, 'ft");
      break;
    case CMP_LE:
      Format(instr, "cmp.le.d  'fd,  'fs, 'ft");
      break;
    case CMP_ULE:
      Format(instr, "cmp.ule.d  'fd,  'fs, 'ft");
      break;
    case CMP_OR:
      Format(instr, "cmp.or.d  'fd,  'fs, 'ft");
      break;
    case CMP_UNE:
      Format(instr, "cmp.une.d  'fd,  'fs, 'ft");
      break;
    case CMP_NE:
      Format(instr, "cmp.ne.d  'fd,  'fs, 'ft");
      break;
    default:
      UNREACHABLE();
  }
}

void Decoder::DecodeTypeRegisterWRsType(Instruction* instr) {
  switch (instr->FunctionValue()) {
    case CVT_S_W:  // Convert word to float (single).
      Format(instr, "cvt.s.w 'fd, 'fs");
      break;
    case CVT_D_W:  // Convert word to double.
      Format(instr, "cvt.d.w 'fd, 'fs");
      break;
    case CMP_AF:
      Format(instr, "cmp.af.s    'fd, 'fs, 'ft");
      break;
    case CMP_UN:
      Format(instr, "cmp.un.s    'fd, 'fs, 'ft");
      break;
    case CMP_EQ:
      Format(instr, "cmp.eq.s    'fd, 'fs, 'ft");
      break;
    case CMP_UEQ:
      Format(instr, "cmp.ueq.s   'fd, 'fs, 'ft");
      break;
    case CMP_LT:
      Format(instr, "cmp.lt.s    'fd, 'fs, 'ft");
      break;
    case CMP_ULT:
      Format(instr, "cmp.ult.s   'fd, 'fs, 'ft");
      break;
    case CMP_LE:
      Format(instr, "cmp.le.s    'fd, 'fs, 'ft");
      break;
    case CMP_ULE:
      Format(instr, "cmp.ule.s   'fd, 'fs, 'ft");
      break;
    case CMP_OR:
      Format(instr, "cmp.or.s    'fd, 'fs, 'ft");
      break;
    case CMP_UNE:
      Format(instr, "cmp.une.s   'fd, 'fs, 'ft");
      break;
    case CMP_NE:
      Format(instr, "cmp.ne.s    'fd, 'fs, 'ft");
      break;
    default:
      UNREACHABLE();
  }
}

void Decoder::DecodeTypeRegisterCOP1(Instruction* instr) {
  switch (instr->RsFieldRaw()) {
    case MFC1:
      Format(instr, "mfc1    'rt, 'fs");
      break;
    case DMFC1:
      Format(instr, "dmfc1    'rt, 'fs");
      break;
    case MFHC1:
      Format(instr, "mfhc1   'rt, 'fs");
      break;
    case MTC1:
      Format(instr, "mtc1    'rt, 'fs");
      break;
    case DMTC1:
      Format(instr, "dmtc1    'rt, 'fs");
      break;
    // These are called "fs" too, although they are not FPU registers.
    case CTC1:
      Format(instr, "ctc1    'rt, 'fs");
      break;
    case CFC1:
      Format(instr, "cfc1    'rt, 'fs");
      break;
    case MTHC1:
      Format(instr, "mthc1   'rt, 'fs");
      break;
    case S:
      DecodeTypeRegisterSRsType(instr);
      break;
    case D:
      DecodeTypeRegisterDRsType(instr);
      break;
    case W:
      DecodeTypeRegisterWRsType(instr);
      break;
    case L:
      DecodeTypeRegisterLRsType(instr);
      break;
    default:
      UNREACHABLE();
  }
}

void Decoder::DecodeTypeRegisterCOP1X(Instruction* instr) {
  switch (instr->FunctionFieldRaw()) {
    case MADD_S:
      Format(instr, "madd.s  'fd, 'fr, 'fs, 'ft");
      break;
    case MADD_D:
      Format(instr, "madd.d  'fd, 'fr, 'fs, 'ft");
      break;
    case MSUB_S:
      Format(instr, "msub.s  'fd, 'fr, 'fs, 'ft");
      break;
    case MSUB_D:
      Format(instr, "msub.d  'fd, 'fr, 'fs, 'ft");
      break;
    default:
      UNREACHABLE();
  }
}

void Decoder::DecodeTypeRegisterSPECIAL(Instruction* instr) {
  switch (instr->FunctionFieldRaw()) {
    case JR:
      Format(instr, "jr      'rs");
      break;
    case JALR:
      Format(instr, "jalr    'rs, 'rd");
      break;
    case SLL:
      if (0x0 == static_cast<int>(instr->InstructionBits()))
        Format(instr, "nop");
      else
        Format(instr, "sll     'rd, 'rt, 'sa");
      break;
    case DSLL:
      Format(instr, "dsll    'rd, 'rt, 'sa");
      break;
    case D_MUL_MUH:  // Equals to DMUL.
      if (kArchVariant != kMips64r6) {
        Format(instr, "dmult   'rs, 'rt");
      } else {
        if (instr->SaValue() == MUL_OP) {
          Format(instr, "dmul   'rd, 'rs, 'rt");
        } else {
          Format(instr, "dmuh   'rd, 'rs, 'rt");
        }
      }
      break;
    case DSLL32:
      Format(instr, "dsll32  'rd, 'rt, 'sa");
      break;
    case SRL:
      if (instr->RsValue() == 0) {
        Format(instr, "srl     'rd, 'rt, 'sa");
      } else {
        Format(instr, "rotr    'rd, 'rt, 'sa");
      }
      break;
    case DSRL:
      if (instr->RsValue() == 0) {
        Format(instr, "dsrl    'rd, 'rt, 'sa");
      } else {
        Format(instr, "drotr   'rd, 'rt, 'sa");
      }
      break;
    case DSRL32:
      if (instr->RsValue() == 0) {
        Format(instr, "dsrl32  'rd, 'rt, 'sa");
      } else {
        Format(instr, "drotr32 'rd, 'rt, 'sa");
      }
      break;
    case SRA:
      Format(instr, "sra     'rd, 'rt, 'sa");
      break;
    case DSRA:
      Format(instr, "dsra    'rd, 'rt, 'sa");
      break;
    case DSRA32:
      Format(instr, "dsra32  'rd, 'rt, 'sa");
      break;
    case SLLV:
      Format(instr, "sllv    'rd, 'rt, 'rs");
      break;
    case DSLLV:
      Format(instr, "dsllv   'rd, 'rt, 'rs");
      break;
    case SRLV:
      if (instr->SaValue() == 0) {
        Format(instr, "srlv    'rd, 'rt, 'rs");
      } else {
        Format(instr, "rotrv   'rd, 'rt, 'rs");
      }
      break;
    case DSRLV:
      if (instr->SaValue() == 0) {
        Format(instr, "dsrlv   'rd, 'rt, 'rs");
      } else {
        Format(instr, "drotrv  'rd, 'rt, 'rs");
      }
      break;
    case SRAV:
      Format(instr, "srav    'rd, 'rt, 'rs");
      break;
    case DSRAV:
      Format(instr, "dsrav   'rd, 'rt, 'rs");
      break;
    case LSA:
      Format(instr, "lsa     'rd, 'rt, 'rs, 'sa2");
      break;
    case DLSA:
      Format(instr, "dlsa    'rd, 'rt, 'rs, 'sa2");
      break;
    case MFHI:
      if (instr->Bits(25, 16) == 0) {
        Format(instr, "mfhi    'rd");
      } else {
        if ((instr->FunctionFieldRaw() == CLZ_R6) && (instr->FdValue() == 1)) {
          Format(instr, "clz     'rd, 'rs");
        } else if ((instr->FunctionFieldRaw() == CLO_R6) &&
                   (instr->FdValue() == 1)) {
          Format(instr, "clo     'rd, 'rs");
        }
      }
      break;
    case MFLO:
      if (instr->Bits(25, 16) == 0) {
        Format(instr, "mflo    'rd");
      } else {
        if ((instr->FunctionFieldRaw() == DCLZ_R6) && (instr->FdValue() == 1)) {
          Format(instr, "dclz    'rd, 'rs");
        } else if ((instr->FunctionFieldRaw() == DCLO_R6) &&
                   (instr->FdValue() == 1)) {
          Format(instr, "dclo     'rd, 'rs");
        }
      }
      break;
    case D_MUL_MUH_U:  // Equals to DMULTU.
      if (kArchVariant != kMips64r6) {
        Format(instr, "dmultu  'rs, 'rt");
      } else {
        if (instr->SaValue() == MUL_OP) {
          Format(instr, "dmulu  'rd, 'rs, 'rt");
        } else {
          Format(instr, "dmuhu  'rd, 'rs, 'rt");
        }
      }
      break;
    case MULT:  // @Mips64r6 == MUL_MUH.
      if (kArchVariant != kMips64r6) {
        Format(instr, "mult    'rs, 'rt");
      } else {
        if (instr->SaValue() == MUL_OP) {
          Format(instr, "mul    'rd, 'rs, 'rt");
        } else {
          Format(instr, "muh    'rd, 'rs, 'rt");
        }
      }
      break;
    case MULTU:  // @Mips64r6 == MUL_MUH_U.
      if (kArchVariant != kMips64r6) {
        Format(instr, "multu   'rs, 'rt");
      } else {
        if (instr->SaValue() == MUL_OP) {
          Format(instr, "mulu   'rd, 'rs, 'rt");
        } else {
          Format(instr, "muhu   'rd, 'rs, 'rt");
        }
      }

      break;
    case DIV:  // @Mips64r6 == DIV_MOD.
      if (kArchVariant != kMips64r6) {
        Format(instr, "div     'rs, 'rt");
      } else {
        if (instr->SaValue() == DIV_OP) {
          Format(instr, "div    'rd, 'rs, 'rt");
        } else {
          Format(instr, "mod    'rd, 'rs, 'rt");
        }
      }
      break;
    case DDIV:  // @Mips64r6 == D_DIV_MOD.
      if (kArchVariant != kMips64r6) {
        Format(instr, "ddiv    'rs, 'rt");
      } else {
        if (instr->SaValue() == DIV_OP) {
          Format(instr, "ddiv   'rd, 'rs, 'rt");
        } else {
          Format(instr, "dmod   'rd, 'rs, 'rt");
        }
      }
      break;
    case DIVU:  // @Mips64r6 == DIV_MOD_U.
      if (kArchVariant != kMips64r6) {
        Format(instr, "divu    'rs, 'rt");
      } else {
        if (instr->SaValue() == DIV_OP) {
          Format(instr, "divu   'rd, 'rs, 'rt");
        } else {
          Format(instr, "modu   'rd, 'rs, 'rt");
        }
      }
      break;
    case DDIVU:  // @Mips64r6 == D_DIV_MOD_U.
      if (kArchVariant != kMips64r6) {
        Format(instr, "ddivu   'rs, 'rt");
      } else {
        if (instr->SaValue() == DIV_OP) {
          Format(instr, "ddivu  'rd, 'rs, 'rt");
        } else {
          Format(instr, "dmodu  'rd, 'rs, 'rt");
        }
      }
      break;
    case ADD:
      Format(instr, "add     'rd, 'rs, 'rt");
      break;
    case DADD:
      Format(instr, "dadd    'rd, 'rs, 'rt");
      break;
    case ADDU:
      Format(instr, "addu    'rd, 'rs, 'rt");
      break;
    case DADDU:
      Format(instr, "daddu   'rd, 'rs, 'rt");
      break;
    case SUB:
      Format(instr, "sub     'rd, 'rs, 'rt");
      break;
    case DSUB:
      Format(instr, "dsub    'rd, 'rs, 'rt");
      break;
    case SUBU:
      Format(instr, "subu    'rd, 'rs, 'rt");
      break;
    case DSUBU:
      Format(instr, "dsubu   'rd, 'rs, 'rt");
      break;
    case AND:
      Format(instr, "and     'rd, 'rs, 'rt");
      break;
    case OR:
      if (0 == instr->RsValue()) {
        Format(instr, "mov     'rd, 'rt");
      } else if (0 == instr->RtValue()) {
        Format(instr, "mov     'rd, 'rs");
      } else {
        Format(instr, "or      'rd, 'rs, 'rt");
      }
      break;
    case XOR:
      Format(instr, "xor     'rd, 'rs, 'rt");
      break;
    case NOR:
      Format(instr, "nor     'rd, 'rs, 'rt");
      break;
    case SLT:
      Format(instr, "slt     'rd, 'rs, 'rt");
      break;
    case SLTU:
      Format(instr, "sltu    'rd, 'rs, 'rt");
      break;
    case TGE:
      Format(instr, "tge     'rs, 'rt, code: 'code");
      break;
    case TGEU:
      Format(instr, "tgeu    'rs, 'rt, code: 'code");
      break;
    case TLT:
      Format(instr, "tlt     'rs, 'rt, code: 'code");
      break;
    case TLTU:
      Format(instr, "tltu    'rs, 'rt, code: 'code");
      break;
    case TEQ:
      Format(instr, "teq     'rs, 'rt, code: 'code");
      break;
    case TNE:
      Format(instr, "tne     'rs, 'rt, code: 'code");
      break;
    case SYNC:
      Format(instr, "sync");
      break;
    case MOVZ:
      Format(instr, "movz    'rd, 'rs, 'rt");
      break;
    case MOVN:
      Format(instr, "movn    'rd, 'rs, 'rt");
      break;
    case MOVCI:
      if (instr->Bit(16)) {
        Format(instr, "movt    'rd, 'rs, 'bc");
      } else {
        Format(instr, "movf    'rd, 'rs, 'bc");
      }
      break;
    case SELEQZ_S:
      Format(instr, "seleqz    'rd, 'rs, 'rt");
      break;
    case SELNEZ_S:
      Format(instr, "selnez    'rd, 'rs, 'rt");
      break;
    default:
      UNREACHABLE();
  }
}

void Decoder::DecodeTypeRegisterSPECIAL2(Instruction* instr) {
  switch (instr->FunctionFieldRaw()) {
    case MUL:
      Format(instr, "mul     'rd, 'rs, 'rt");
      break;
    case CLZ:
      if (kArchVariant != kMips64r6) {
        Format(instr, "clz     'rd, 'rs");
      }
      break;
    case DCLZ:
      if (kArchVariant != kMips64r6) {
        Format(instr, "dclz    'rd, 'rs");
      }
      break;
    default:
      UNREACHABLE();
  }
}

void Decoder::DecodeTypeRegisterSPECIAL3(Instruction* instr) {
  switch (instr->FunctionFieldRaw()) {
    case EXT: {
      Format(instr, "ext     'rt, 'rs, 'sa, 'ss1");
      break;
    }
    case DEXT: {
      Format(instr, "dext    'rt, 'rs, 'sa, 'ss1");
      break;
    }
    case DEXTM: {
      Format(instr, "dextm   'rt, 'rs, 'sa, 'ss3");
      break;
    }
    case DEXTU: {
      Format(instr, "dextu   'rt, 'rs, 'ss5, 'ss1");
      break;
    }
    case INS: {
      Format(instr, "ins     'rt, 'rs, 'sa, 'ss2");
      break;
    }
    case DINS: {
      Format(instr, "dins    'rt, 'rs, 'sa, 'ss2");
      break;
    }
    case DINSM: {
      Format(instr, "dinsm   'rt, 'rs, 'sa, 'ss4");
      break;
    }
    case DINSU: {
      Format(instr, "dinsu   'rt, 'rs, 'ss5, 'ss2");
      break;
    }
    case BSHFL: {
      int sa = instr->SaFieldRaw() >> kSaShift;
      switch (sa) {
        case BITSWAP: {
          Format(instr, "bitswap 'rd, 'rt");
          break;
        }
        case SEB: {
          Format(instr, "seb     'rd, 'rt");
          break;
        }
        case SEH: {
          Format(instr, "seh     'rd, 'rt");
          break;
        }
        case WSBH: {
          Format(instr, "wsbh    'rd, 'rt");
          break;
        }
        default: {
          sa >>= kBp2Bits;
          switch (sa) {
            case ALIGN: {
              Format(instr, "align  'rd, 'rs, 'rt, 'bp2");
              break;
            }
            default:
              UNREACHABLE();
          }
          break;
        }
      }
      break;
    }
    case DBSHFL: {
      int sa = instr->SaFieldRaw() >> kSaShift;
      switch (sa) {
        case DBITSWAP: {
          switch (instr->SaFieldRaw() >> kSaShift) {
            case DBITSWAP_SA:
              Format(instr, "dbitswap 'rd, 'rt");
              break;
            default:
              UNREACHABLE();
          }
          break;
        }
        case DSBH: {
          Format(instr, "dsbh    'rd, 'rt");
          break;
        }
        case DSHD: {
          Format(instr, "dshd    'rd, 'rt");
          break;
        }
        default: {
          sa >>= kBp3Bits;
          switch (sa) {
            case DALIGN: {
              Format(instr, "dalign  'rd, 'rs, 'rt, 'bp3");
              break;
            }
            default:
              UNREACHABLE();
          }
          break;
        }
      }
      break;
    }
    default:
      UNREACHABLE();
  }
}

int Decoder::DecodeTypeRegister(Instruction* instr) {
  switch (instr->OpcodeFieldRaw()) {
    case COP1:  // Coprocessor instructions.
      DecodeTypeRegisterCOP1(instr);
      break;
    case COP1X:
      DecodeTypeRegisterCOP1X(instr);
      break;
    case SPECIAL:
      switch (instr->FunctionFieldRaw()) {
        case BREAK:
          return DecodeBreakInstr(instr);
        default:
          DecodeTypeRegisterSPECIAL(instr);
          break;
      }
      break;
    case SPECIAL2:
      DecodeTypeRegisterSPECIAL2(instr);
      break;
    case SPECIAL3:
      DecodeTypeRegisterSPECIAL3(instr);
      break;
    case MSA:
      switch (instr->MSAMinorOpcodeField()) {
        case kMsaMinor3R:
          DecodeTypeMsa3R(instr);
          break;
        case kMsaMinor3RF:
          DecodeTypeMsa3RF(instr);
          break;
        case kMsaMinorVEC:
          DecodeTypeMsaVec(instr);
          break;
        case kMsaMinor2R:
          DecodeTypeMsa2R(instr);
          break;
        case kMsaMinor2RF:
          DecodeTypeMsa2RF(instr);
          break;
        case kMsaMinorELM:
          DecodeTypeMsaELM(instr);
          break;
        default:
          UNREACHABLE();
      }
      break;
    default:
      UNREACHABLE();
  }
  return kInstrSize;
}

void Decoder::DecodeTypeImmediateCOP1(Instruction* instr) {
  switch (instr->RsFieldRaw()) {
    case BC1:
      if (instr->FBtrueValue()) {
        Format(instr, "bc1t    'bc, 'imm16u -> 'imm16p4s2");
      } else {
        Format(instr, "bc1f    'bc, 'imm16u -> 'imm16p4s2");
      }
      break;
    case BC1EQZ:
      Format(instr, "bc1eqz    'ft, 'imm16u -> 'imm16p4s2");
      break;
    case BC1NEZ:
      Format(instr, "bc1nez    'ft, 'imm16u -> 'imm16p4s2");
      break;
    case BZ_V:
    case BZ_B:
    case BZ_H:
    case BZ_W:
    case BZ_D:
      Format(instr, "bz.'t  'wt, 'imm16s -> 'imm16p4s2");
      break;
    case BNZ_V:
    case BNZ_B:
    case BNZ_H:
    case BNZ_W:
    case BNZ_D:
      Format(instr, "bnz.'t  'wt, 'imm16s -> 'imm16p4s2");
      break;
    default:
      UNREACHABLE();
  }
}

void Decoder::DecodeTypeImmediateREGIMM(Instruction* instr) {
  switch (instr->RtFieldRaw()) {
    case BLTZ:
      Format(instr, "bltz    'rs, 'imm16u -> 'imm16p4s2");
      break;
    case BLTZAL:
      Format(instr, "bltzal  'rs, 'imm16u -> 'imm16p4s2");
      break;
    case BGEZ:
      Format(instr, "bgez    'rs, 'imm16u -> 'imm16p4s2");
      break;
    case BGEZAL: {
      if (instr->RsValue() == 0)
        Format(instr, "bal     'imm16s -> 'imm16p4s2");
      else
        Format(instr, "bgezal  'rs, 'imm16u -> 'imm16p4s2");
      break;
    }
    case BGEZALL:
      Format(instr, "bgezall 'rs, 'imm16u -> 'imm16p4s2");
      break;
    case DAHI:
      Format(instr, "dahi    'rs, 'imm16x");
      break;
    case DATI:
      Format(instr, "dati    'rs, 'imm16x");
      break;
    default:
      UNREACHABLE();
  }
}

void Decoder::DecodeTypeImmediateSPECIAL3(Instruction* instr) {
  switch (instr->FunctionFieldRaw()) {
    case LL_R6: {
      if (kArchVariant == kMips64r6) {
        Format(instr, "ll     'rt, 'imm9s('rs)");
      } else {
        Unknown(instr);
      }
      break;
    }
    case LLD_R6: {
      if (kArchVariant == kMips64r6) {
        Format(instr, "lld     'rt, 'imm9s('rs)");
      } else {
        Unknown(instr);
      }
      break;
    }
    case SC_R6: {
      if (kArchVariant == kMips64r6) {
        Format(instr, "sc     'rt, 'imm9s('rs)");
      } else {
        Unknown(instr);
      }
      break;
    }
    case SCD_R6: {
      if (kArchVariant == kMips64r6) {
        Format(instr, "scd     'rt, 'imm9s('rs)");
      } else {
        Unknown(instr);
      }
      break;
    }
    default:
      UNREACHABLE();
  }
}

void Decoder::DecodeTypeImmediate(Instruction* instr) {
  switch (instr->OpcodeFieldRaw()) {
    case COP1:
      DecodeTypeImmediateCOP1(instr);
      break;  // Case COP1.
    // ------------- REGIMM class.
    case REGIMM:
      DecodeTypeImmediateREGIMM(instr);
      break;  // Case REGIMM.
    // ------------- Branch instructions.
    case BEQ:
      Format(instr, "beq     'rs, 'rt, 'imm16u -> 'imm16p4s2");
      break;
    case BC:
      Format(instr, "bc      'imm26s -> 'imm26p4s2");
      break;
    case BALC:
      Format(instr, "balc    'imm26s -> 'imm26p4s2");
      break;
    case BNE:
      Format(instr, "bne     'rs, 'rt, 'imm16u -> 'imm16p4s2");
      break;
    case BLEZ:
      if ((instr->RtValue() == 0) && (instr->RsValue() != 0)) {
        Format(instr, "blez    'rs, 'imm16u -> 'imm16p4s2");
      } else if ((instr->RtValue() != instr->RsValue()) &&
                 (instr->RsValue() != 0) && (instr->RtValue() != 0)) {
        Format(instr, "bgeuc   'rs, 'rt, 'imm16u -> 'imm16p4s2");
      } else if ((instr->RtValue() == instr->RsValue()) &&
                 (instr->RtValue() != 0)) {
        Format(instr, "bgezalc 'rs, 'imm16u -> 'imm16p4s2");
      } else if ((instr->RsValue() == 0) && (instr->RtValue() != 0)) {
        Format(instr, "blezalc 'rt, 'imm16u -> 'imm16p4s2");
      } else {
        UNREACHABLE();
      }
      break;
    case BGTZ:
      if ((instr->RtValue() == 0) && (instr->RsValue() != 0)) {
        Format(instr, "bgtz    'rs, 'imm16u -> 'imm16p4s2");
      } else if ((instr->RtValue() != instr->RsValue()) &&
                 (instr->RsValue() != 0) && (instr->RtValue() != 0)) {
        Format(instr, "bltuc   'rs, 'rt, 'imm16u -> 'imm16p4s2");
      } else if ((instr->RtValue() == instr->RsValue()) &&
                 (instr->RtValue() != 0)) {
        Format(instr, "bltzalc 'rt, 'imm16u -> 'imm16p4s2");
      } else if ((instr->RsValue() == 0) && (instr->RtValue() != 0)) {
        Format(instr, "bgtzalc 'rt, 'imm16u -> 'imm16p4s2");
      } else {
        UNREACHABLE();
      }
      break;
    case BLEZL:
      if ((instr->RtValue() == instr->RsValue()) && (instr->RtValue() != 0)) {
        Format(instr, "bgezc    'rt, 'imm16u -> 'imm16p4s2");
      } else if ((instr->RtValue() != instr->RsValue()) &&
                 (instr->RsValue() != 0) && (instr->RtValue() != 0)) {
        Format(instr, "bgec     'rs, 'rt, 'imm16u -> 'imm16p4s2");
      } else if ((instr->RsValue() == 0) && (instr->RtValue() != 0)) {
        Format(instr, "blezc    'rt, 'imm16u -> 'imm16p4s2");
      } else {
        UNREACHABLE();
      }
      break;
    case BGTZL:
      if ((instr->RtValue() == instr->RsValue()) && (instr->RtValue() != 0)) {
        Format(instr, "bltzc    'rt, 'imm16u -> 'imm16p4s2");
      } else if ((instr->RtValue() != instr->RsValue()) &&
                 (instr->RsValue() != 0) && (instr->RtValue() != 0)) {
        Format(instr, "bltc    'rs, 'rt, 'imm16u -> 'imm16p4s2");
      } else if ((instr->RsValue() == 0) && (instr->RtValue() != 0)) {
        Format(instr, "bgtzc    'rt, 'imm16u -> 'imm16p4s2");
      } else {
        UNREACHABLE();
      }
      break;
    case POP66:
      if (instr->RsValue() == JIC) {
        Format(instr, "jic     'rt, 'imm16s");
      } else {
        Format(instr, "beqzc   'rs, 'imm21s -> 'imm21p4s2");
      }
      break;
    case POP76:
      if (instr->RsValue() == JIALC) {
        Format(instr, "jialc   'rt, 'imm16s");
      } else {
        Format(instr, "bnezc   'rs, 'imm21s -> 'imm21p4s2");
      }
      break;
    // ------------- Arithmetic instructions.
    case ADDI:
      if (kArchVariant != kMips64r6) {
        Format(instr, "addi    'rt, 'rs, 'imm16s");
      } else {
        int rs_reg = instr->RsValue();
        int rt_reg = instr->RtValue();
        // Check if BOVC, BEQZALC or BEQC instruction.
        if (rs_reg >= rt_reg) {
          Format(instr, "bovc  'rs, 'rt, 'imm16s -> 'imm16p4s2");
        } else {
          DCHECK_GT(rt_reg, 0);
          if (rs_reg == 0) {
            Format(instr, "beqzalc 'rt, 'imm16s -> 'imm16p4s2");
          } else {
            Format(instr, "beqc    'rs, 'rt, 'imm16s -> 'imm16p4s2");
          }
        }
      }
      break;
    case DADDI:
      if (kArchVariant != kMips64r6) {
        Format(instr, "daddi   'rt, 'rs, 'imm16s");
      } else {
        int rs_reg = instr->RsValue();
        int rt_reg = instr->RtValue();
        // Check if BNVC, BNEZALC or BNEC instruction.
        if (rs_reg >= rt_reg) {
          Format(instr, "bnvc  'rs, 'rt, 'imm16s -> 'imm16p4s2");
        } else {
          DCHECK_GT(rt_reg, 0);
          if (rs_reg == 0) {
            Format(instr, "bnezalc 'rt, 'imm16s -> 'imm16p4s2");
          } else {
            Format(instr, "bnec  'rs, 'rt, 'imm16s -> 'imm16p4s2");
          }
        }
      }
      break;
    case ADDIU:
      Format(instr, "addiu   'rt, 'rs, 'imm16s");
      break;
    case DADDIU:
      Format(instr, "daddiu  'rt, 'rs, 'imm16s");
      break;
    case SLTI:
      Format(instr, "slti    'rt, 'rs, 'imm16s");
      break;
    case SLTIU:
      Format(instr, "sltiu   'rt, 'rs, 'imm16u");
      break;
    case ANDI:
      Format(instr, "andi    'rt, 'rs, 'imm16x");
      break;
    case ORI:
      Format(instr, "ori     'rt, 'rs, 'imm16x");
      break;
    case XORI:
      Format(instr, "xori    'rt, 'rs, 'imm16x");
      break;
    case LUI:
      if (kArchVariant != kMips64r6) {
        Format(instr, "lui     'rt, 'imm16x");
      } else {
        if (instr->RsValue() != 0) {
          Format(instr, "aui     'rt, 'rs, 'imm16x");
        } else {
          Format(instr, "lui     'rt, 'imm16x");
        }
      }
      break;
    case DAUI:
      Format(instr, "daui    'rt, 'rs, 'imm16x");
      break;
    // ------------- Memory instructions.
    case LB:
      Format(instr, "lb      'rt, 'imm16s('rs)");
      break;
    case LH:
      Format(instr, "lh      'rt, 'imm16s('rs)");
      break;
    case LWL:
      Format(instr, "lwl     'rt, 'imm16s('rs)");
      break;
    case LDL:
      Format(instr, "ldl     'rt, 'imm16s('rs)");
      break;
    case LW:
      Format(instr, "lw      'rt, 'imm16s('rs)");
      break;
    case LWU:
      Format(instr, "lwu     'rt, 'imm16s('rs)");
      break;
    case LD:
      Format(instr, "ld      'rt, 'imm16s('rs)");
      break;
    case LBU:
      Format(instr, "lbu     'rt, 'imm16s('rs)");
      break;
    case LHU:
      Format(instr, "lhu     'rt, 'imm16s('rs)");
      break;
    case LWR:
      Format(instr, "lwr     'rt, 'imm16s('rs)");
      break;
    case LDR:
      Format(instr, "ldr     'rt, 'imm16s('rs)");
      break;
    case PREF:
      Format(instr, "pref    'rt, 'imm16s('rs)");
      break;
    case SB:
      Format(instr, "sb      'rt, 'imm16s('rs)");
      break;
    case SH:
      Format(instr, "sh      'rt, 'imm16s('rs)");
      break;
    case SWL:
      Format(instr, "swl     'rt, 'imm16s('rs)");
      break;
    case SW:
      Format(instr, "sw      'rt, 'imm16s('rs)");
      break;
    case SD:
      Format(instr, "sd      'rt, 'imm16s('rs)");
      break;
    case SWR:
      Format(instr, "swr     'rt, 'imm16s('rs)");
      break;
    case SDR:
      Format(instr, "sdr     'rt, 'imm16s('rs)");
      break;
    case SDL:
      Format(instr, "sdl     'rt, 'imm16s('rs)");
      break;
    case LL:
      if (kArchVariant == kMips64r6) {
        Unknown(instr);
      } else {
        Format(instr, "ll     'rt, 'imm16s('rs)");
      }
      break;
    case LLD:
      if (kArchVariant == kMips64r6) {
        Unknown(instr);
      } else {
        Format(instr, "lld     'rt, 'imm16s('rs)");
      }
      break;
    case SC:
      if (kArchVariant == kMips64r6) {
        Unknown(instr);
      } else {
        Format(instr, "sc     'rt, 'imm16s('rs)");
      }
      break;
    case SCD:
      if (kArchVariant == kMips64r6) {
        Unknown(instr);
      } else {
        Format(instr, "scd     'rt, 'imm16s('rs)");
      }
      break;
    case LWC1:
      Format(instr, "lwc1    'ft, 'imm16s('rs)");
      break;
    case LDC1:
      Format(
"""


```