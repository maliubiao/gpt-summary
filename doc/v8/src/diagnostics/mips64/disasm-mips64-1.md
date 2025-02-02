Response: The user wants me to summarize the functionality of the provided C++ code snippet. This code is part of the V8 JavaScript engine and specifically focuses on disassembling MIPS64 architecture instructions.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core purpose:** The file name `disasm-mips64.cc` and the presence of functions like `InstructionDecode` and `Disassemble` strongly suggest that this code is responsible for disassembling MIPS64 instructions. Disassembling means converting machine code into a human-readable assembly language representation.

2. **Examine key classes and functions:**
    * `Decoder`: This class seems to be the central component. Its methods like `DecodeTypeRegister`, `DecodeTypeImmediate`, `DecodeTypeJump`, and various `DecodeTypeMsa...` functions indicate different ways to decode various MIPS64 instruction formats.
    * `Format`: This function likely takes an instruction and a format string and populates the output buffer with the disassembled instruction.
    * `Instruction`: This class (not fully defined in the snippet but clearly used) likely represents a single MIPS64 instruction and provides methods to access its fields (opcode, operands, etc.).
    * `Disassembler`: This class provides the high-level `Disassemble` function, which iterates through a block of memory and disassembles each instruction.
    * `NameConverter`: This class handles the conversion of addresses and registers to human-readable names.

3. **Trace the decoding process:** The `InstructionDecode` function in the `Decoder` class appears to be the entry point for disassembling a single instruction. It determines the instruction type and then calls the appropriate `DecodeType...` function. These functions further break down the instruction based on its opcode and format, extracting operands and formatting the output.

4. **Identify MIPS64 specific aspects:** The code includes handling for various MIPS64 instruction formats and extensions like MSA (MIPS SIMD Architecture), which are specific to that architecture. The switch statements based on opcode and minor opcode values are crucial for correctly identifying and disassembling different instructions.

5. **Consider the relationship with JavaScript:** V8 is a JavaScript engine. The disassembler plays a role in debugging and introspection. When the engine needs to understand or display the low-level machine code being executed (e.g., during debugging or profiling), this code is used to convert the raw bytes into a readable form. This allows developers to see the actual machine instructions generated by the JavaScript code.

6. **Construct the summary for Part 2:** Since this is Part 2, I need to focus on the code provided in this specific snippet. I should mention the `Decoder` class and its role in individual instruction decoding, the handling of different instruction types (register, immediate, jump, MSA), and the formatting of the output.

7. **Illustrate with a JavaScript example (if applicable):** To show the connection to JavaScript, I need to demonstrate a scenario where this disassembler might be used. Debugging and performance analysis are the most common use cases. I can show a simple JavaScript function and explain that tools could use this disassembler to show the generated MIPS64 code.

8. **Review and refine:**  Ensure the summary is clear, concise, and accurately reflects the functionality of the code. Check for any technical jargon that might need clarification. Make sure the JavaScript example clearly demonstrates the connection.
好的，这是v8/src/diagnostics/mips64/disasm-mips64.cc文件的第二部分，延续了第一部分的功能，主要负责 **解码和格式化 MIPS64 架构的指令，以便将其转换为人类可读的汇编代码**。

具体来说，这部分代码实现了 `Decoder` 类的更多方法，用于处理不同类型的 MIPS64 指令：

* **针对不同指令类型的解码函数：**
    * `DecodeTypeImmediate`: 处理立即数类型的指令。
    * `DecodeTypeJump`: 处理跳转类型的指令。
    * `DecodeTypeMsaI8`, `DecodeTypeMsaI5`, `DecodeTypeMsaI10`, `DecodeTypeMsaELM`, `DecodeTypeMsaBIT`, `DecodeTypeMsaMI10`, `DecodeTypeMsa3R`, `DecodeTypeMsa3RF`, `DecodeTypeMsaVec`, `DecodeTypeMsa2R`, `DecodeTypeMsa2RF`:  这些函数专门用于解码 MIPS SIMD Architecture (MSA) 的各种指令，MSA 是 MIPS64 架构的向量扩展。

* **指令格式化：**
    * 大量使用 `Format` 函数，这个函数可能在第一部分定义，它的作用是将解码后的指令信息按照预定义的格式输出到缓冲区。格式字符串中使用了占位符（如 `'ft`, `'rs`, `'imm16s` 等）来表示不同的操作数。
    * 针对 MSA 指令，还存在一些辅助的格式化函数，例如 `PrintMSAControlRegister` 和 `PrintMsaCopy`，用于打印特定的 MSA 寄存器和操作数。

* **处理各种 MIPS64 指令：**  代码中包含了大量的 `switch` 语句，根据指令的操作码和子操作码来识别具体的指令，并调用相应的格式化方式。这涵盖了算术运算、逻辑运算、加载/存储、跳转、浮点运算以及各种 MSA 指令。

* **`InstructionDecode` 函数：**  这是解码单个指令的入口点。它根据指令的类型调用相应的解码函数，并将解码后的汇编代码写入输出缓冲区。

* **`Disassembler` 类和相关辅助类：**
    * `NameConverter`:  用于将地址、常量和寄存器名称转换为可读的字符串表示。
    * `Disassembler`:  提供 `InstructionDecode` 的外部接口，用于解码单个指令，并且提供了 `Disassemble` 函数，用于解码一段内存中的多个指令。

**与 JavaScript 的关系：**

这段代码是 V8 JavaScript 引擎的一部分，它的主要作用是在需要查看 JavaScript 代码对应的底层机器码时使用，例如在调试器中或者进行性能分析时。

**JavaScript 示例：**

假设你在 V8 的调试器中设置了一个断点，或者你使用了性能分析工具来查看某个 JavaScript 函数的执行情况。V8 可能会使用这里的反汇编代码来向你展示该函数编译后的 MIPS64 汇编指令。

例如，考虑以下简单的 JavaScript 函数：

```javascript
function add(a, b) {
  return a + b;
}
```

当 V8 引擎编译这个函数并在 MIPS64 架构上执行时，它会被转换为一系列的机器指令。  `disasm-mips64.cc` 中的代码就负责将这些机器指令转换成类似下面的汇编表示：

```assembly
  # (假设的汇编输出，实际输出会更复杂)
  lw      $t0, [sp+16]   # 加载参数 a
  lw      $t1, [sp+24]   # 加载参数 b
  add     $v0, $t0, $t1   # 执行加法
  sw      $v0, [sp+8]    # 保存结果
  jr      $ra            # 返回
```

这段反汇编代码可以帮助开发者理解 JavaScript 代码在底层是如何执行的，尤其是在进行性能优化或者调试一些底层问题时非常有用。  对于 MSA 指令，反汇编输出会显示向量化的操作，这可以帮助理解 V8 如何利用 SIMD 指令来提升性能。

总而言之，`disasm-mips64.cc` 的第二部分继续完善了 MIPS64 指令的反汇编功能，使其能够处理更广泛的指令集，特别是 MSA 扩展，从而为 V8 引擎在 MIPS64 架构上的调试和性能分析提供了重要的支持。

### 提示词
```
这是目录为v8/src/diagnostics/mips64/disasm-mips64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```
instr, "ldc1    'ft, 'imm16s('rs)");
      break;
    case SWC1:
      Format(instr, "swc1    'ft, 'imm16s('rs)");
      break;
    case SDC1:
      Format(instr, "sdc1    'ft, 'imm16s('rs)");
      break;
    case PCREL: {
      int32_t imm21 = instr->Imm21Value();
      // rt field: 5-bits checking
      uint8_t rt = (imm21 >> kImm16Bits);
      switch (rt) {
        case ALUIPC:
          Format(instr, "aluipc  'rs, 'imm16s");
          break;
        case AUIPC:
          Format(instr, "auipc   'rs, 'imm16s");
          break;
        default: {
          // rt field: checking of the most significant 3-bits
          rt = (imm21 >> kImm18Bits);
          switch (rt) {
            case LDPC:
              Format(instr, "ldpc    'rs, 'imm18s");
              break;
            default: {
              // rt field: checking of the most significant 2-bits
              rt = (imm21 >> kImm19Bits);
              switch (rt) {
                case LWUPC:
                  Format(instr, "lwupc   'rs, 'imm19s");
                  break;
                case LWPC:
                  Format(instr, "lwpc    'rs, 'imm19s");
                  break;
                case ADDIUPC:
                  Format(instr, "addiupc 'rs, 'imm19s");
                  break;
                default:
                  UNREACHABLE();
              }
              break;
            }
          }
          break;
        }
      }
      break;
    }
    case SPECIAL3:
      DecodeTypeImmediateSPECIAL3(instr);
      break;
    case MSA:
      switch (instr->MSAMinorOpcodeField()) {
        case kMsaMinorI8:
          DecodeTypeMsaI8(instr);
          break;
        case kMsaMinorI5:
          DecodeTypeMsaI5(instr);
          break;
        case kMsaMinorI10:
          DecodeTypeMsaI10(instr);
          break;
        case kMsaMinorELM:
          DecodeTypeMsaELM(instr);
          break;
        case kMsaMinorBIT:
          DecodeTypeMsaBIT(instr);
          break;
        case kMsaMinorMI10:
          DecodeTypeMsaMI10(instr);
          break;
        default:
          UNREACHABLE();
      }
      break;
    default:
      printf("a 0x%x \n", instr->OpcodeFieldRaw());
      UNREACHABLE();
  }
}

void Decoder::DecodeTypeJump(Instruction* instr) {
  switch (instr->OpcodeFieldRaw()) {
    case J:
      Format(instr, "j       'imm26x -> 'imm26j");
      break;
    case JAL:
      Format(instr, "jal     'imm26x -> 'imm26j");
      break;
    default:
      UNREACHABLE();
  }
}

void Decoder::DecodeTypeMsaI8(Instruction* instr) {
  uint32_t opcode = instr->InstructionBits() & kMsaI8Mask;

  switch (opcode) {
    case ANDI_B:
      Format(instr, "andi.b  'wd, 'ws, 'imm8");
      break;
    case ORI_B:
      Format(instr, "ori.b  'wd, 'ws, 'imm8");
      break;
    case NORI_B:
      Format(instr, "nori.b  'wd, 'ws, 'imm8");
      break;
    case XORI_B:
      Format(instr, "xori.b  'wd, 'ws, 'imm8");
      break;
    case BMNZI_B:
      Format(instr, "bmnzi.b  'wd, 'ws, 'imm8");
      break;
    case BMZI_B:
      Format(instr, "bmzi.b  'wd, 'ws, 'imm8");
      break;
    case BSELI_B:
      Format(instr, "bseli.b  'wd, 'ws, 'imm8");
      break;
    case SHF_B:
      Format(instr, "shf.b  'wd, 'ws, 'imm8");
      break;
    case SHF_H:
      Format(instr, "shf.h  'wd, 'ws, 'imm8");
      break;
    case SHF_W:
      Format(instr, "shf.w  'wd, 'ws, 'imm8");
      break;
    default:
      UNREACHABLE();
  }
}

void Decoder::DecodeTypeMsaI5(Instruction* instr) {
  uint32_t opcode = instr->InstructionBits() & kMsaI5Mask;

  switch (opcode) {
    case ADDVI:
      Format(instr, "addvi.'t  'wd, 'ws, 'imm5u");
      break;
    case SUBVI:
      Format(instr, "subvi.'t  'wd, 'ws, 'imm5u");
      break;
    case MAXI_S:
      Format(instr, "maxi_s.'t  'wd, 'ws, 'imm5s");
      break;
    case MAXI_U:
      Format(instr, "maxi_u.'t  'wd, 'ws, 'imm5u");
      break;
    case MINI_S:
      Format(instr, "mini_s.'t  'wd, 'ws, 'imm5s");
      break;
    case MINI_U:
      Format(instr, "mini_u.'t  'wd, 'ws, 'imm5u");
      break;
    case CEQI:
      Format(instr, "ceqi.'t  'wd, 'ws, 'imm5s");
      break;
    case CLTI_S:
      Format(instr, "clti_s.'t  'wd, 'ws, 'imm5s");
      break;
    case CLTI_U:
      Format(instr, "clti_u.'t  'wd, 'ws, 'imm5u");
      break;
    case CLEI_S:
      Format(instr, "clei_s.'t  'wd, 'ws, 'imm5s");
      break;
    case CLEI_U:
      Format(instr, "clei_u.'t  'wd, 'ws, 'imm5u");
      break;
    default:
      UNREACHABLE();
  }
}

void Decoder::DecodeTypeMsaI10(Instruction* instr) {
  uint32_t opcode = instr->InstructionBits() & kMsaI5Mask;
  if (opcode == LDI) {
    Format(instr, "ldi.'t  'wd, 'imm10s1");
  } else {
    UNREACHABLE();
  }
}

void Decoder::DecodeTypeMsaELM(Instruction* instr) {
  uint32_t opcode = instr->InstructionBits() & kMsaELMMask;
  switch (opcode) {
    case SLDI:
      if (instr->Bits(21, 16) == 0x3E) {
        Format(instr, "ctcmsa  ");
        PrintMSAControlRegister(instr->WdValue());
        Print(", ");
        PrintRegister(instr->WsValue());
      } else {
        Format(instr, "sldi.'t  'wd, 'ws['imme]");
      }
      break;
    case SPLATI:
      if (instr->Bits(21, 16) == 0x3E) {
        Format(instr, "cfcmsa  ");
        PrintRegister(instr->WdValue());
        Print(", ");
        PrintMSAControlRegister(instr->WsValue());
      } else {
        Format(instr, "splati.'t  'wd, 'ws['imme]");
      }
      break;
    case COPY_S:
      if (instr->Bits(21, 16) == 0x3E) {
        Format(instr, "move.v  'wd, 'ws");
      } else {
        Format(instr, "copy_s.'t  ");
        PrintMsaCopy(instr);
      }
      break;
    case COPY_U:
      Format(instr, "copy_u.'t  ");
      PrintMsaCopy(instr);
      break;
    case INSERT:
      Format(instr, "insert.'t  'wd['imme], ");
      PrintRegister(instr->WsValue());
      break;
    case INSVE:
      Format(instr, "insve.'t  'wd['imme], 'ws[0]");
      break;
    default:
      UNREACHABLE();
  }
}

void Decoder::DecodeTypeMsaBIT(Instruction* instr) {
  uint32_t opcode = instr->InstructionBits() & kMsaBITMask;

  switch (opcode) {
    case SLLI:
      Format(instr, "slli.'t  'wd, 'ws, 'immb");
      break;
    case SRAI:
      Format(instr, "srai.'t  'wd, 'ws, 'immb");
      break;
    case SRLI:
      Format(instr, "srli.'t  'wd, 'ws, 'immb");
      break;
    case BCLRI:
      Format(instr, "bclri.'t  'wd, 'ws, 'immb");
      break;
    case BSETI:
      Format(instr, "bseti.'t  'wd, 'ws, 'immb");
      break;
    case BNEGI:
      Format(instr, "bnegi.'t  'wd, 'ws, 'immb");
      break;
    case BINSLI:
      Format(instr, "binsli.'t  'wd, 'ws, 'immb");
      break;
    case BINSRI:
      Format(instr, "binsri.'t  'wd, 'ws, 'immb");
      break;
    case SAT_S:
      Format(instr, "sat_s.'t  'wd, 'ws, 'immb");
      break;
    case SAT_U:
      Format(instr, "sat_u.'t  'wd, 'ws, 'immb");
      break;
    case SRARI:
      Format(instr, "srari.'t  'wd, 'ws, 'immb");
      break;
    case SRLRI:
      Format(instr, "srlri.'t  'wd, 'ws, 'immb");
      break;
    default:
      UNREACHABLE();
  }
}

void Decoder::DecodeTypeMsaMI10(Instruction* instr) {
  uint32_t opcode = instr->InstructionBits() & kMsaMI10Mask;
  if (opcode == MSA_LD) {
    Format(instr, "ld.'t  'wd, 'imm10s2(");
    PrintRegister(instr->WsValue());
    Print(")");
  } else if (opcode == MSA_ST) {
    Format(instr, "st.'t  'wd, 'imm10s2(");
    PrintRegister(instr->WsValue());
    Print(")");
  } else {
    UNREACHABLE();
  }
}

void Decoder::DecodeTypeMsa3R(Instruction* instr) {
  uint32_t opcode = instr->InstructionBits() & kMsa3RMask;
  switch (opcode) {
    case SLL_MSA:
      Format(instr, "sll.'t  'wd, 'ws, 'wt");
      break;
    case SRA_MSA:
      Format(instr, "sra.'t  'wd, 'ws, 'wt");
      break;
    case SRL_MSA:
      Format(instr, "srl.'t  'wd, 'ws, 'wt");
      break;
    case BCLR:
      Format(instr, "bclr.'t  'wd, 'ws, 'wt");
      break;
    case BSET:
      Format(instr, "bset.'t  'wd, 'ws, 'wt");
      break;
    case BNEG:
      Format(instr, "bneg.'t  'wd, 'ws, 'wt");
      break;
    case BINSL:
      Format(instr, "binsl.'t  'wd, 'ws, 'wt");
      break;
    case BINSR:
      Format(instr, "binsr.'t  'wd, 'ws, 'wt");
      break;
    case ADDV:
      Format(instr, "addv.'t  'wd, 'ws, 'wt");
      break;
    case SUBV:
      Format(instr, "subv.'t  'wd, 'ws, 'wt");
      break;
    case MAX_S:
      Format(instr, "max_s.'t  'wd, 'ws, 'wt");
      break;
    case MAX_U:
      Format(instr, "max_u.'t  'wd, 'ws, 'wt");
      break;
    case MIN_S:
      Format(instr, "min_s.'t  'wd, 'ws, 'wt");
      break;
    case MIN_U:
      Format(instr, "min_u.'t  'wd, 'ws, 'wt");
      break;
    case MAX_A:
      Format(instr, "max_a.'t  'wd, 'ws, 'wt");
      break;
    case MIN_A:
      Format(instr, "min_a.'t  'wd, 'ws, 'wt");
      break;
    case CEQ:
      Format(instr, "ceq.'t  'wd, 'ws, 'wt");
      break;
    case CLT_S:
      Format(instr, "clt_s.'t  'wd, 'ws, 'wt");
      break;
    case CLT_U:
      Format(instr, "clt_u.'t  'wd, 'ws, 'wt");
      break;
    case CLE_S:
      Format(instr, "cle_s.'t  'wd, 'ws, 'wt");
      break;
    case CLE_U:
      Format(instr, "cle_u.'t  'wd, 'ws, 'wt");
      break;
    case ADD_A:
      Format(instr, "add_a.'t  'wd, 'ws, 'wt");
      break;
    case ADDS_A:
      Format(instr, "adds_a.'t  'wd, 'ws, 'wt");
      break;
    case ADDS_S:
      Format(instr, "adds_s.'t  'wd, 'ws, 'wt");
      break;
    case ADDS_U:
      Format(instr, "adds_u.'t  'wd, 'ws, 'wt");
      break;
    case AVE_S:
      Format(instr, "ave_s.'t  'wd, 'ws, 'wt");
      break;
    case AVE_U:
      Format(instr, "ave_u.'t  'wd, 'ws, 'wt");
      break;
    case AVER_S:
      Format(instr, "aver_s.'t  'wd, 'ws, 'wt");
      break;
    case AVER_U:
      Format(instr, "aver_u.'t  'wd, 'ws, 'wt");
      break;
    case SUBS_S:
      Format(instr, "subs_s.'t  'wd, 'ws, 'wt");
      break;
    case SUBS_U:
      Format(instr, "subs_u.'t  'wd, 'ws, 'wt");
      break;
    case SUBSUS_U:
      Format(instr, "subsus_u.'t  'wd, 'ws, 'wt");
      break;
    case SUBSUU_S:
      Format(instr, "subsuu_s.'t  'wd, 'ws, 'wt");
      break;
    case ASUB_S:
      Format(instr, "asub_s.'t  'wd, 'ws, 'wt");
      break;
    case ASUB_U:
      Format(instr, "asub_u.'t  'wd, 'ws, 'wt");
      break;
    case MULV:
      Format(instr, "mulv.'t  'wd, 'ws, 'wt");
      break;
    case MADDV:
      Format(instr, "maddv.'t  'wd, 'ws, 'wt");
      break;
    case MSUBV:
      Format(instr, "msubv.'t  'wd, 'ws, 'wt");
      break;
    case DIV_S_MSA:
      Format(instr, "div_s.'t  'wd, 'ws, 'wt");
      break;
    case DIV_U:
      Format(instr, "div_u.'t  'wd, 'ws, 'wt");
      break;
    case MOD_S:
      Format(instr, "mod_s.'t  'wd, 'ws, 'wt");
      break;
    case MOD_U:
      Format(instr, "mod_u.'t  'wd, 'ws, 'wt");
      break;
    case DOTP_S:
      Format(instr, "dotp_s.'t  'wd, 'ws, 'wt");
      break;
    case DOTP_U:
      Format(instr, "dotp_u.'t  'wd, 'ws, 'wt");
      break;
    case DPADD_S:
      Format(instr, "dpadd_s.'t  'wd, 'ws, 'wt");
      break;
    case DPADD_U:
      Format(instr, "dpadd_u.'t  'wd, 'ws, 'wt");
      break;
    case DPSUB_S:
      Format(instr, "dpsub_s.'t  'wd, 'ws, 'wt");
      break;
    case DPSUB_U:
      Format(instr, "dpsub_u.'t  'wd, 'ws, 'wt");
      break;
    case SLD:
      Format(instr, "sld.'t  'wd, 'ws['rt]");
      break;
    case SPLAT:
      Format(instr, "splat.'t  'wd, 'ws['rt]");
      break;
    case PCKEV:
      Format(instr, "pckev.'t  'wd, 'ws, 'wt");
      break;
    case PCKOD:
      Format(instr, "pckod.'t  'wd, 'ws, 'wt");
      break;
    case ILVL:
      Format(instr, "ilvl.'t  'wd, 'ws, 'wt");
      break;
    case ILVR:
      Format(instr, "ilvr.'t  'wd, 'ws, 'wt");
      break;
    case ILVEV:
      Format(instr, "ilvev.'t  'wd, 'ws, 'wt");
      break;
    case ILVOD:
      Format(instr, "ilvod.'t  'wd, 'ws, 'wt");
      break;
    case VSHF:
      Format(instr, "vshf.'t  'wd, 'ws, 'wt");
      break;
    case SRAR:
      Format(instr, "srar.'t  'wd, 'ws, 'wt");
      break;
    case SRLR:
      Format(instr, "srlr.'t  'wd, 'ws, 'wt");
      break;
    case HADD_S:
      Format(instr, "hadd_s.'t  'wd, 'ws, 'wt");
      break;
    case HADD_U:
      Format(instr, "hadd_u.'t  'wd, 'ws, 'wt");
      break;
    case HSUB_S:
      Format(instr, "hsub_s.'t  'wd, 'ws, 'wt");
      break;
    case HSUB_U:
      Format(instr, "hsub_u.'t  'wd, 'ws, 'wt");
      break;
    default:
      UNREACHABLE();
  }
}

void Decoder::DecodeTypeMsa3RF(Instruction* instr) {
  uint32_t opcode = instr->InstructionBits() & kMsa3RFMask;
  switch (opcode) {
    case FCAF:
      Format(instr, "fcaf.'t  'wd, 'ws, 'wt");
      break;
    case FCUN:
      Format(instr, "fcun.'t  'wd, 'ws, 'wt");
      break;
    case FCEQ:
      Format(instr, "fceq.'t  'wd, 'ws, 'wt");
      break;
    case FCUEQ:
      Format(instr, "fcueq.'t  'wd, 'ws, 'wt");
      break;
    case FCLT:
      Format(instr, "fclt.'t  'wd, 'ws, 'wt");
      break;
    case FCULT:
      Format(instr, "fcult.'t  'wd, 'ws, 'wt");
      break;
    case FCLE:
      Format(instr, "fcle.'t  'wd, 'ws, 'wt");
      break;
    case FCULE:
      Format(instr, "fcule.'t  'wd, 'ws, 'wt");
      break;
    case FSAF:
      Format(instr, "fsaf.'t  'wd, 'ws, 'wt");
      break;
    case FSUN:
      Format(instr, "fsun.'t  'wd, 'ws, 'wt");
      break;
    case FSEQ:
      Format(instr, "fseq.'t  'wd, 'ws, 'wt");
      break;
    case FSUEQ:
      Format(instr, "fsueq.'t  'wd, 'ws, 'wt");
      break;
    case FSLT:
      Format(instr, "fslt.'t  'wd, 'ws, 'wt");
      break;
    case FSULT:
      Format(instr, "fsult.'t  'wd, 'ws, 'wt");
      break;
    case FSLE:
      Format(instr, "fsle.'t  'wd, 'ws, 'wt");
      break;
    case FSULE:
      Format(instr, "fsule.'t  'wd, 'ws, 'wt");
      break;
    case FADD:
      Format(instr, "fadd.'t  'wd, 'ws, 'wt");
      break;
    case FSUB:
      Format(instr, "fsub.'t  'wd, 'ws, 'wt");
      break;
    case FMUL:
      Format(instr, "fmul.'t  'wd, 'ws, 'wt");
      break;
    case FDIV:
      Format(instr, "fdiv.'t  'wd, 'ws, 'wt");
      break;
    case FMADD:
      Format(instr, "fmadd.'t  'wd, 'ws, 'wt");
      break;
    case FMSUB:
      Format(instr, "fmsub.'t  'wd, 'ws, 'wt");
      break;
    case FEXP2:
      Format(instr, "fexp2.'t  'wd, 'ws, 'wt");
      break;
    case FEXDO:
      Format(instr, "fexdo.'t  'wd, 'ws, 'wt");
      break;
    case FTQ:
      Format(instr, "ftq.'t  'wd, 'ws, 'wt");
      break;
    case FMIN:
      Format(instr, "fmin.'t  'wd, 'ws, 'wt");
      break;
    case FMIN_A:
      Format(instr, "fmin_a.'t  'wd, 'ws, 'wt");
      break;
    case FMAX:
      Format(instr, "fmax.'t  'wd, 'ws, 'wt");
      break;
    case FMAX_A:
      Format(instr, "fmax_a.'t  'wd, 'ws, 'wt");
      break;
    case FCOR:
      Format(instr, "fcor.'t  'wd, 'ws, 'wt");
      break;
    case FCUNE:
      Format(instr, "fcune.'t  'wd, 'ws, 'wt");
      break;
    case FCNE:
      Format(instr, "fcne.'t  'wd, 'ws, 'wt");
      break;
    case MUL_Q:
      Format(instr, "mul_q.'t  'wd, 'ws, 'wt");
      break;
    case MADD_Q:
      Format(instr, "madd_q.'t  'wd, 'ws, 'wt");
      break;
    case MSUB_Q:
      Format(instr, "msub_q.'t  'wd, 'ws, 'wt");
      break;
    case FSOR:
      Format(instr, "fsor.'t  'wd, 'ws, 'wt");
      break;
    case FSUNE:
      Format(instr, "fsune.'t  'wd, 'ws, 'wt");
      break;
    case FSNE:
      Format(instr, "fsne.'t  'wd, 'ws, 'wt");
      break;
    case MULR_Q:
      Format(instr, "mulr_q.'t  'wd, 'ws, 'wt");
      break;
    case MADDR_Q:
      Format(instr, "maddr_q.'t  'wd, 'ws, 'wt");
      break;
    case MSUBR_Q:
      Format(instr, "msubr_q.'t  'wd, 'ws, 'wt");
      break;
    default:
      UNREACHABLE();
  }
}

void Decoder::DecodeTypeMsaVec(Instruction* instr) {
  uint32_t opcode = instr->InstructionBits() & kMsaVECMask;
  switch (opcode) {
    case AND_V:
      Format(instr, "and.v  'wd, 'ws, 'wt");
      break;
    case OR_V:
      Format(instr, "or.v  'wd, 'ws, 'wt");
      break;
    case NOR_V:
      Format(instr, "nor.v  'wd, 'ws, 'wt");
      break;
    case XOR_V:
      Format(instr, "xor.v  'wd, 'ws, 'wt");
      break;
    case BMNZ_V:
      Format(instr, "bmnz.v  'wd, 'ws, 'wt");
      break;
    case BMZ_V:
      Format(instr, "bmz.v  'wd, 'ws, 'wt");
      break;
    case BSEL_V:
      Format(instr, "bsel.v  'wd, 'ws, 'wt");
      break;
    default:
      UNREACHABLE();
  }
}

void Decoder::DecodeTypeMsa2R(Instruction* instr) {
  uint32_t opcode = instr->InstructionBits() & kMsa2RMask;
  switch (opcode) {
    case FILL: {
      Format(instr, "fill.'t  'wd, ");
      PrintRegister(instr->WsValue());  // rs value is in ws field
    } break;
    case PCNT:
      Format(instr, "pcnt.'t  'wd, 'ws");
      break;
    case NLOC:
      Format(instr, "nloc.'t  'wd, 'ws");
      break;
    case NLZC:
      Format(instr, "nlzc.'t  'wd, 'ws");
      break;
    default:
      UNREACHABLE();
  }
}

void Decoder::DecodeTypeMsa2RF(Instruction* instr) {
  uint32_t opcode = instr->InstructionBits() & kMsa2RFMask;
  switch (opcode) {
    case FCLASS:
      Format(instr, "fclass.'t  'wd, 'ws");
      break;
    case FTRUNC_S:
      Format(instr, "ftrunc_s.'t  'wd, 'ws");
      break;
    case FTRUNC_U:
      Format(instr, "ftrunc_u.'t  'wd, 'ws");
      break;
    case FSQRT:
      Format(instr, "fsqrt.'t  'wd, 'ws");
      break;
    case FRSQRT:
      Format(instr, "frsqrt.'t  'wd, 'ws");
      break;
    case FRCP:
      Format(instr, "frcp.'t  'wd, 'ws");
      break;
    case FRINT:
      Format(instr, "frint.'t  'wd, 'ws");
      break;
    case FLOG2:
      Format(instr, "flog2.'t  'wd, 'ws");
      break;
    case FEXUPL:
      Format(instr, "fexupl.'t  'wd, 'ws");
      break;
    case FEXUPR:
      Format(instr, "fexupr.'t  'wd, 'ws");
      break;
    case FFQL:
      Format(instr, "ffql.'t  'wd, 'ws");
      break;
    case FFQR:
      Format(instr, "ffqr.'t  'wd, 'ws");
      break;
    case FTINT_S:
      Format(instr, "ftint_s.'t  'wd, 'ws");
      break;
    case FTINT_U:
      Format(instr, "ftint_u.'t  'wd, 'ws");
      break;
    case FFINT_S:
      Format(instr, "ffint_s.'t  'wd, 'ws");
      break;
    case FFINT_U:
      Format(instr, "ffint_u.'t  'wd, 'ws");
      break;
    default:
      UNREACHABLE();
  }
}

// Disassemble the instruction at *instr_ptr into the output buffer.
// All instructions are one word long, except for the simulator
// pseudo-instruction stop(msg). For that one special case, we return
// size larger than one kInstrSize.
int Decoder::InstructionDecode(uint8_t* instr_ptr) {
  Instruction* instr = Instruction::At(instr_ptr);
  // Print raw instruction bytes.
  out_buffer_pos_ += base::SNPrintF(out_buffer_ + out_buffer_pos_,
                                    "%08x       ", instr->InstructionBits());
  switch (instr->InstructionType()) {
    case Instruction::kRegisterType: {
      return DecodeTypeRegister(instr);
    }
    case Instruction::kImmediateType: {
      DecodeTypeImmediate(instr);
      break;
    }
    case Instruction::kJumpType: {
      DecodeTypeJump(instr);
      break;
    }
    default: {
      Format(instr, "UNSUPPORTED");
      UNSUPPORTED_MIPS();
    }
  }
  return kInstrSize;
}

}  // namespace internal
}  // namespace v8

//------------------------------------------------------------------------------

namespace disasm {

const char* NameConverter::NameOfAddress(uint8_t* addr) const {
  v8::base::SNPrintF(tmp_buffer_, "%p", static_cast<void*>(addr));
  return tmp_buffer_.begin();
}

const char* NameConverter::NameOfConstant(uint8_t* addr) const {
  return NameOfAddress(addr);
}

const char* NameConverter::NameOfCPURegister(int reg) const {
  return v8::internal::Registers::Name(reg);
}

const char* NameConverter::NameOfXMMRegister(int reg) const {
  return v8::internal::FPURegisters::Name(reg);
}

const char* NameConverter::NameOfByteCPURegister(int reg) const {
  UNREACHABLE();  // MIPS does not have the concept of a byte register.
}

const char* NameConverter::NameInCode(uint8_t* addr) const {
  // The default name converter is called for unknown code. So we will not try
  // to access any memory.
  return "";
}

//------------------------------------------------------------------------------

int Disassembler::InstructionDecode(v8::base::Vector<char> buffer,
                                    uint8_t* instruction) {
  v8::internal::Decoder d(converter_, buffer);
  return d.InstructionDecode(instruction);
}

// The MIPS assembler does not currently use constant pools.
int Disassembler::ConstantPoolSizeAt(uint8_t* instruction) { return -1; }

void Disassembler::Disassemble(FILE* f, uint8_t* begin, uint8_t* end,
                               UnimplementedOpcodeAction unimplemented_action) {
  NameConverter converter;
  Disassembler d(converter, unimplemented_action);
  for (uint8_t* pc = begin; pc < end;) {
    v8::base::EmbeddedVector<char, 128> buffer;
    buffer[0] = '\0';
    uint8_t* prev_pc = pc;
    pc += d.InstructionDecode(buffer, pc);
    v8::internal::PrintF(f, "%p    %08x      %s\n", static_cast<void*>(prev_pc),
                         *reinterpret_cast<int32_t*>(prev_pc), buffer.begin());
  }
}

#undef STRING_STARTS_WITH

}  // namespace disasm

#endif  // V8_TARGET_ARCH_MIPS64
```