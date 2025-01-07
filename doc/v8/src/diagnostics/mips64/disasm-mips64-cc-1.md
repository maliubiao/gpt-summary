Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the V8 JavaScript engine and specifically targets the MIPS64 architecture for disassembly.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core purpose:** The filename `disasm-mips64.cc` strongly suggests this code is responsible for disassembling MIPS64 machine code. Disassembly means converting raw machine instructions back into a human-readable assembly language representation.

2. **Examine the class name:** The `Decoder` class is central to the code. This reinforces the idea that the code is involved in the process of decoding instructions.

3. **Analyze key methods:**
    * `Format`: This method takes an `Instruction` and a format string. The presence of escape characters like `'t`, `'fd`, `'rs` indicates it's substituting values from the instruction into the format string to produce the assembly output.
    * `FormatOption`: This handles the parsing of the escape sequences within the format string.
    * `Decode*`:  Multiple `Decode` methods exist for different instruction types (e.g., `DecodeTypeRegister`, `DecodeTypeImmediate`). This points to a structured approach to handling various MIPS64 instruction formats.
    * `Unknown`: This function handles cases where the instruction cannot be decoded, printing "unknown".
    * `DecodeBreakInstr`: Specifically handles the `break` instruction, which can have embedded data.

4. **Look for patterns in formatting:** The format strings within the `Decode` methods are crucial. They reveal the mnemonics and operand structures of different MIPS64 instructions. For example, `Format(instr, "add     'rd, 'rs, 'rt");` shows how the `add` instruction is formatted.

5. **Check for conditional logic:**  `switch` statements based on opcode fields (`instr->OpcodeFieldRaw()`, `instr->FunctionFieldRaw()`, etc.) are used to differentiate instruction types and apply the correct formatting.

6. **Consider the 't' case in `FormatOption`:** This seems to handle different output formats based on whether the instruction is an MSA (MIPS SIMD Architecture) instruction or a standard instruction.

7. **Infer data flow:**  The `Decoder` takes an `Instruction` as input and populates an `out_buffer_` with the disassembled representation.

8. **Address the specific questions:**
    * **Functionality:**  Disassemble MIPS64 instructions.
    * **Torque:** The filename ends with `.cc`, not `.tq`, so it's not Torque.
    * **JavaScript relation:**  Disassembly is indirectly related to JavaScript as V8 compiles JavaScript to machine code, and this code helps analyze that machine code for debugging or introspection. Provide a simple JavaScript example of a function.
    * **Logic inference (example):**  Choose a simple instruction like `add`. Provide an example input instruction (hypothetical bit pattern) and the expected output string.
    * **Common programming errors:**  Disassembly helps debug errors, like incorrect opcode usage or wrong operand order. Provide a C++ example that would lead to an unexpected disassembled output.

9. **Summarize the functionality:**  Reiterate the main purpose in concise terms, focusing on input (machine code) and output (assembly representation).

**Self-Correction/Refinement during thought process:**

* **Initial thought:** Maybe it's just about printing instruction details.
* **Correction:** The presence of distinct `Decode` methods for various instruction formats indicates a more complex decoding process, not just simple printing.
* **Initial thought:** How does it relate to JavaScript directly?
* **Refinement:** It's an *indirect* relationship through the compilation process. It's a tool for analyzing the generated machine code.
* **Initial thought:**  Just describe the methods.
* **Refinement:**  Explain the *purpose* of the methods in the context of disassembly.

By following this process, focusing on the code's structure, naming conventions, and the purpose of individual functions, a comprehensive and accurate summary can be generated.
这是v8源代码文件`v8/src/diagnostics/mips64/disasm-mips64.cc`的第二部分，延续了第一部分的功能，主要负责 **将MIPS64架构的机器码指令解码并格式化成人类可读的汇编代码字符串**。

**归纳一下它的功能:**

这部分代码主要实现了 `Decoder` 类的以下功能：

1. **处理指令格式选项 (`FormatOption`):**  根据指令的类型和字段，提取指令中的操作数、寄存器、立即数等信息，并根据格式字符串进行替换和打印。 例如，`'rs'` 会被替换成 `rs` 寄存器的名称。

2. **格式化指令输出 (`Format`):**  接收一个指令对象和一个格式字符串，遍历格式字符串，遇到转义字符 `'` 时调用 `FormatOption` 处理，否则直接将字符添加到输出缓冲区。

3. **处理未知指令 (`Unknown`):**  对于无法识别或尚未实现的指令解码，会打印 "unknown"。

4. **解码 `break` 指令 (`DecodeBreakInstr`):**  专门处理 `break` 指令，可以提取 `break` 指令中的代码，并且对于 `stop(msg)` 形式的 `break` 指令，还会打印嵌入的 64 位字符指针。

5. **解码各种类型的寄存器操作指令 (`DecodeTypeRegister*`):**
   - 根据指令的功能字段（Function Field），识别不同的寄存器操作指令，例如算术运算、逻辑运算、浮点运算等。
   - 使用相应的格式字符串，将指令解码成汇编代码，包括操作码和操作数。
   - 细化了对不同浮点操作指令（S, D, W, L 类型）的处理。
   - 处理了 MIPS64r6 特有的指令。

6. **解码协处理器 1 (COP1) 相关指令 (`DecodeTypeRegisterCOP1`, `DecodeTypeRegisterCOP1X`):** 处理浮点运算相关的指令。

7. **解码特殊指令 (`DecodeTypeRegisterSPECIAL`, `DecodeTypeRegisterSPECIAL2`, `DecodeTypeRegisterSPECIAL3`):**  处理各种特殊功能的指令，例如跳转、移位、乘除法、比较等。

8. **解码 MSA (MIPS SIMD Architecture) 指令 (`DecodeTypeRegister`):**  处理 MIPS 向量扩展指令。

9. **解码立即数操作指令 (`DecodeTypeImmediate*`):**
   - 处理带有立即数的指令，例如分支指令、算术运算指令、访存指令等。
   - 根据指令类型，提取立即数并进行格式化，可能包括符号扩展和移位。
   - 针对不同的分支指令 (`BEQ`, `BNE`, `BLEZ`, `BGTZ` 等) 进行解码。
   - 处理了 MIPS64r6 特有的立即数操作指令。

**与 JavaScript 功能的关系:**

`v8/src/diagnostics/mips64/disasm-mips64.cc` 的功能与 JavaScript 的执行密切相关，但不是直接的 JavaScript 代码。它的作用在于 **帮助开发者理解和调试 V8 生成的 MIPS64 机器码**。

例如，当 V8 编译一段 JavaScript 代码时：

```javascript
function add(a, b) {
  return a + b;
}
```

V8 可能会将其编译成一系列 MIPS64 指令。 `disasm-mips64.cc` 的功能就是将这些 MIPS64 指令转换成汇编代码，方便开发者查看编译器生成的具体指令序列，进行性能分析或错误排查。

**代码逻辑推理 (假设输入与输出):**

**假设输入:** 一个代表 MIPS64 `add` 指令的 `Instruction` 对象，其内部的二进制表示为 `010000 sssss ttttt ddddd 00000 100000` (这是一个简化的示意，实际二进制码会更复杂)，其中 `sssss` 代表 `rs` 寄存器编号，`ttttt` 代表 `rt` 寄存器编号，`ddddd` 代表 `rd` 寄存器编号。

**假设 `rs` 对应寄存器 `r2`，`rt` 对应寄存器 `r3`，`rd` 对应寄存器 `r4`。**

**输出:**  `add     r4, r2, r3`

**解释:**  `DecodeTypeRegisterSPECIAL` 函数会根据指令的 `FunctionFieldRaw()` 判断这是 `add` 指令，然后 `Format` 函数会使用格式字符串 `"add     'rd, 'rs, 'rt"`，并调用 `FormatOption` 将 `'rd'` 替换为 `r4`，`'rs'` 替换为 `r2`，`'rt'` 替换为 `r3`，最终生成汇编代码字符串。

**涉及用户常见的编程错误:**

虽然这个文件本身不是用户直接编写的代码，但它在调试用户代码时非常有用。常见的编程错误可能导致 V8 生成意外的机器码，通过查看反汇编输出可以帮助定位问题。

**例如，在 C++ 中，一个常见的错误是类型不匹配导致编译器生成非预期的指令:**

```c++
int a = 5;
long long b = 10;
long long c = a + b; // 这里会发生隐式类型转换
```

如果 V8 基于某些原因将这段 C++ 代码编译成 MIPS64，并且类型转换的处理方式与预期不符，那么查看反汇编输出可能会揭示问题所在。  例如，可能会发现编译器并没有生成期望的 64 位加法指令，而是先将 `a` 转换成 64 位，然后再进行加法。

**总结一下这部分代码的功能:**

这部分 `disasm-mips64.cc` 实现了 MIPS64 架构指令集的大部分解码和格式化功能，能够将机器码指令转换成可读的汇编代码字符串，用于 V8 引擎的调试和代码分析。它涵盖了寄存器操作、协处理器操作、特殊指令以及立即数操作等多种指令类型。

Prompt: 
```
这是目录为v8/src/diagnostics/mips64/disasm-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/diagnostics/mips64/disasm-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
RTS_WITH(format, "bp3"));
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