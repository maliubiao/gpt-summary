Response: The user wants to understand the functionality of the provided C++ code snippet, which is the second part of a larger file. The code is located in `v8/src/diagnostics/ia32/disasm-ia32.cc` and deals with disassembling IA-32 instructions.

To answer this, I need to:
1. **Summarize the functionality of this code snippet.** This involves analyzing the different `case` statements within the `InstructionDecode` function to understand which IA-32 instructions are handled here.
2. **Determine if and how this code relates to JavaScript.**  V8 is a JavaScript engine, so this disassembler is used to understand the underlying machine code generated for JavaScript execution.
3. **Provide a JavaScript example.** This will illustrate how the instructions disassembled by this code might arise from JavaScript code.

Based on the code, it seems to handle instructions starting with opcodes `0x8F`, `0xFF`, `0xC7`, `0xC6`, `0x80`, `0x88`, `0x89`, `0x66`, `0xFE`, `0x68`, `0x6A`, `0xA8`, `0xA9`, `0xD1`, `0xD3`, `0xC1`, `0xD8` to `0xDF`, `0xEB`, `0xF2`, `0xF3`, and `0xF7`. Many of these handlers involve looking at ModR/M bytes to further decode the instruction and operands. There is also specific handling for prefixes like `0x66`. SSE instructions are also handled.

The connection to JavaScript is through V8's compilation process. When JavaScript code is executed by V8, it is often compiled into machine code for the target architecture (in this case, IA-32). This disassembler helps in understanding and debugging that generated machine code.
这是 `v8/src/diagnostics/ia32/disasm-ia32.cc` 文件的第二部分，它延续了第一部分的功能，**负责将 IA-32 (x86) 架构的机器码指令解码并以可读的汇编格式输出**。

**具体来说，这部分代码实现了 `DisassemblerIA32::InstructionDecode` 函数中的更多指令解码逻辑。**  它针对不同的机器码字节序列进行匹配，识别出对应的 IA-32 指令及其操作数，并将这些信息格式化输出到缓冲区。

**核心功能包括：**

* **处理多种 IA-32 指令:**  代码中大量的 `case` 语句对应了不同的 IA-32 指令的操作码。根据操作码，代码会进一步解析 ModR/M 字节、SIB 字节、立即数等，以确定指令的操作数类型和值。
* **输出汇编格式:**  `AppendToBuffer` 函数被用来构建汇编指令的字符串表示，包括指令助记符和操作数。
* **处理前缀:**  例如，`0x66` 前缀用于指示操作数为 16 位，代码中有相应的处理逻辑。
* **处理 SSE 指令:**  代码中包含了对 SSE 和 SSE2 等扩展指令集的解码，例如 `movupd`, `movapd`, `pblendvb` 等。
* **处理 FPU 指令:**  `FPUInstruction` 函数用于处理浮点运算指令。
* **处理各种操作数类型:**  代码中可以看到对寄存器、立即数、内存地址等不同操作数类型的处理和格式化输出。

**与 JavaScript 的关系：**

V8 是一个 JavaScript 引擎，它将 JavaScript 代码编译成机器码以提高执行效率。 这个反汇编器 (`disasm-ia32.cc`) 是 V8 调试工具的一部分。 **当需要查看 V8 生成的 IA-32 机器码时，这个文件中的代码就发挥作用，将这些机器码转换成人类可读的汇编语言，帮助开发者理解 JavaScript 代码是如何在底层执行的，以及进行性能分析和调试。**

**JavaScript 例子：**

以下是一个简单的 JavaScript 例子，以及 V8 在 IA-32 架构下可能生成的部分机器码，并用这个反汇编器解码后的汇编形式：

**JavaScript 代码：**

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
```

**可能的 IA-32 机器码 (仅为示例，实际生成代码会更复杂)：**

假设 `add` 函数被编译成如下（简化的）机器码片段：

```
55          // push   ebp
89 e5       // mov    ebp,esp
8b 45 08    // mov    eax,DWORD PTR [ebp+0x8]  (加载参数 a)
03 45 0c    // add    eax,DWORD PTR [ebp+0xc]  (加上参数 b)
5d          // pop    ebp
c3          // ret
```

**使用 `disasm-ia32.cc` 解码后的汇编输出 (部分):**

```
xxxxxxxx  55             push ebp
xxxxxxxx  89e5           mov ebp,esp
xxxxxxxx  8b4508         mov eax,[ebp+0x8]
xxxxxxxx  03450c         add eax,[ebp+0xc]
xxxxxxxx  5d             pop ebp
xxxxxxxx  c3             ret
```

**解释:**

* **`push ebp`**:  在函数调用开始时，将 `ebp` 寄存器的值压入栈中。
* **`mov ebp,esp`**: 将栈指针 `esp` 的值赋给 `ebp`，建立当前函数的栈帧。
* **`mov eax,[ebp+0x8]`**: 将 `ebp` 加上偏移 0x8 处的内存值（通常是函数的第一个参数 `a`）加载到 `eax` 寄存器中。
* **`add eax,[ebp+0xc]`**: 将 `ebp` 加上偏移 0xc 处的内存值（通常是函数的第二个参数 `b`）加到 `eax` 寄存器的值上。
* **`pop ebp`**: 从栈中弹出之前保存的 `ebp` 的值，恢复调用者的栈帧。
* **`ret`**:  从函数返回。

**总结:**

这部分 `disasm-ia32.cc` 代码是 V8 引擎中用于 IA-32 架构的指令反汇编器的一部分，它负责将机器码指令转换成可读的汇编格式，这对于理解 V8 如何执行 JavaScript 代码、进行性能分析和调试非常重要。 JavaScript 代码最终会被 V8 编译成类似上述示例的机器码，而这个反汇编器就能帮助开发者理解这些底层的指令。

### 提示词
```
这是目录为v8/src/diagnostics/ia32/disasm-ia32.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```
NameOfCPURegister(regop), static_cast<int>(imm8));
        } else if (f0byte == 0xAB || f0byte == 0xA5 || f0byte == 0xAD) {
          // shrd_cl, shld_cl, bts
          data += 2;
          AppendToBuffer("%s ", f0mnem);
          data += PrintRightOperand(data);
          if (f0byte == 0xAB) {
            AppendToBuffer(",%s", NameOfCPURegister(regop));
          } else {
            AppendToBuffer(",%s,cl", NameOfCPURegister(regop));
          }
        } else if (f0byte == 0xB0) {
          // cmpxchg_b
          data += 2;
          AppendToBuffer("%s ", f0mnem);
          data += PrintRightOperand(data);
          AppendToBuffer(",%s", NameOfByteCPURegister(regop));
        } else if (f0byte == 0xB1) {
          // cmpxchg
          data += 2;
          data += PrintOperands(f0mnem, OPER_REG_OP_ORDER, data);
        } else if (f0byte == 0xBC) {
          data += 2;
          AppendToBuffer("%s %s,", f0mnem, NameOfCPURegister(regop));
          data += PrintRightOperand(data);
        } else if (f0byte == 0xBD) {
          data += 2;
          AppendToBuffer("%s %s,", f0mnem, NameOfCPURegister(regop));
          data += PrintRightOperand(data);
        } else if (f0byte == 0xC7) {
          // cmpxchg8b
          data += 2;
          AppendToBuffer("%s ", f0mnem);
          data += PrintRightOperand(data);
        } else if (f0byte == 0xAE && (data[2] & 0xF8) == 0xF0) {
          AppendToBuffer("mfence");
          data += 3;
        } else if (f0byte == 0xAE && (data[2] & 0xF8) == 0xE8) {
          AppendToBuffer("lfence");
          data += 3;
        } else {
          UnimplementedInstruction();
          data += 1;
        }
      } break;

      case 0x8F: {
        data++;
        int mod, regop, rm;
        get_modrm(*data, &mod, &regop, &rm);
        if (regop == eax) {
          AppendToBuffer("pop ");
          data += PrintRightOperand(data);
        }
      } break;

      case 0xFF: {
        data++;
        int mod, regop, rm;
        get_modrm(*data, &mod, &regop, &rm);
        const char* mnem = "";
        switch (regop) {
          case esi:
            mnem = "push";
            break;
          case eax:
            mnem = "inc";
            break;
          case ecx:
            mnem = "dec";
            break;
          case edx:
            mnem = "call";
            break;
          case esp:
            mnem = "jmp";
            break;
          default:
            mnem = "???";
        }
        AppendToBuffer("%s ", mnem);
        data += PrintRightOperand(data);
      } break;

      case 0xC7:  // imm32, fall through
      case 0xC6:  // imm8
      {
        bool is_byte = *data == 0xC6;
        data++;
        if (is_byte) {
          AppendToBuffer("%s ", "mov_b");
          data += PrintRightByteOperand(data);
          int32_t imm = *data;
          AppendToBuffer(",0x%x", imm);
          data++;
        } else {
          AppendToBuffer("%s ", "mov");
          data += PrintRightOperand(data);
          AppendToBuffer(",0x%x", Imm32(data));
          data += 4;
        }
      } break;

      case 0x80: {
        data++;
        int mod, regop, rm;
        get_modrm(*data, &mod, &regop, &rm);
        const char* mnem = "";
        switch (regop) {
          case 5:
            mnem = "subb";
            break;
          case 7:
            mnem = "cmpb";
            break;
          default:
            UnimplementedInstruction();
        }
        AppendToBuffer("%s ", mnem);
        data += PrintRightByteOperand(data);
        int32_t imm = *data;
        AppendToBuffer(",0x%x", imm);
        data++;
      } break;

      case 0x88:  // 8bit, fall through
      case 0x89:  // 32bit
      {
        bool is_byte = *data == 0x88;
        int mod, regop, rm;
        data++;
        get_modrm(*data, &mod, &regop, &rm);
        if (is_byte) {
          AppendToBuffer("%s ", "mov_b");
          data += PrintRightByteOperand(data);
          AppendToBuffer(",%s", NameOfByteCPURegister(regop));
        } else {
          AppendToBuffer("%s ", "mov");
          data += PrintRightOperand(data);
          AppendToBuffer(",%s", NameOfCPURegister(regop));
        }
      } break;

      case 0x66:  // prefix
        while (*data == 0x66) data++;
        if (*data == 0xF && data[1] == 0x1F) {
          AppendToBuffer("nop");  // 0x66 prefix
        } else if (*data == 0x39) {
          data++;
          data += PrintOperands("cmpw", OPER_REG_OP_ORDER, data);
        } else if (*data == 0x3B) {
          data++;
          data += PrintOperands("cmpw", REG_OPER_OP_ORDER, data);
        } else if (*data == 0x81) {
          data++;
          AppendToBuffer("cmpw ");
          data += PrintRightOperand(data);
          AppendToBuffer(",0x%x", Imm16(data));
          data += 2;
        } else if (*data == 0x87) {
          data++;
          int mod, regop, rm;
          get_modrm(*data, &mod, &regop, &rm);
          AppendToBuffer("xchg_w %s,", NameOfCPURegister(regop));
          data += PrintRightOperand(data);
        } else if (*data == 0x89) {
          data++;
          int mod, regop, rm;
          get_modrm(*data, &mod, &regop, &rm);
          AppendToBuffer("mov_w ");
          data += PrintRightOperand(data);
          AppendToBuffer(",%s", NameOfCPURegister(regop));
        } else if (*data == 0x8B) {
          data++;
          data += PrintOperands("mov_w", REG_OPER_OP_ORDER, data);
        } else if (*data == 0x90) {
          AppendToBuffer("nop");  // 0x66 prefix
        } else if (*data == 0xC7) {
          data++;
          AppendToBuffer("%s ", "mov_w");
          data += PrintRightOperand(data);
          AppendToBuffer(",0x%x", Imm16(data));
          data += 2;
        } else if (*data == 0xF7) {
          data++;
          AppendToBuffer("%s ", "test_w");
          data += PrintRightOperand(data);
          AppendToBuffer(",0x%x", Imm16(data));
          data += 2;
        } else if (*data == 0x0F) {
          data++;
          if (*data == 0x10) {
            data++;
            int mod, regop, rm;
            get_modrm(*data, &mod, &regop, &rm);
            AppendToBuffer("movupd %s,", NameOfXMMRegister(regop));
            data += PrintRightXMMOperand(data);
          } else if (*data == 0x28) {
            data++;
            int mod, regop, rm;
            get_modrm(*data, &mod, &regop, &rm);
            AppendToBuffer("movapd %s,", NameOfXMMRegister(regop));
            data += PrintRightXMMOperand(data);
          } else if (*data == 0x38) {
            data++;
            uint8_t op = *data;
            data++;
            int mod, regop, rm;
            get_modrm(*data, &mod, &regop, &rm);
            switch (op) {
#define SSE34_DIS_CASE(instruction, notUsed1, notUsed2, notUsed3, opcode) \
  case 0x##opcode: {                                                      \
    AppendToBuffer(#instruction " %s,", NameOfXMMRegister(regop));        \
    data += PrintRightXMMOperand(data);                                   \
    break;                                                                \
  }

              SSSE3_INSTRUCTION_LIST(SSE34_DIS_CASE)
              SSSE3_UNOP_INSTRUCTION_LIST(SSE34_DIS_CASE)
              SSE4_INSTRUCTION_LIST(SSE34_DIS_CASE)
              SSE4_RM_INSTRUCTION_LIST(SSE34_DIS_CASE)
#undef SSE34_DIS_CASE
              case 0x10:
                AppendToBuffer("pblendvb %s,", NameOfXMMRegister(regop));
                data += PrintRightXMMOperand(data);
                AppendToBuffer(",xmm0");
                break;
              case 0x14:
                AppendToBuffer("blendvps %s,", NameOfXMMRegister(regop));
                data += PrintRightXMMOperand(data);
                AppendToBuffer(",xmm0");
                break;
              case 0x15:
                AppendToBuffer("blendvps %s,", NameOfXMMRegister(regop));
                data += PrintRightXMMOperand(data);
                AppendToBuffer(",xmm0");
                break;
              case 0x37:
                AppendToBuffer("pcmpgtq %s,", NameOfXMMRegister(regop));
                data += PrintRightXMMOperand(data);
                break;
              default:
                UnimplementedInstruction();
            }
          } else if (*data == 0x3A) {
            data++;
            if (*data >= 0x08 && *data <= 0x0B) {
              const char* const pseudo_op[] = {
                  "roundps",
                  "roundpd",
                  "roundss",
                  "roundsd",
              };
              uint8_t op = *data;
              data++;
              int mod, regop, rm;
              get_modrm(*data, &mod, &regop, &rm);
              int8_t imm8 = static_cast<int8_t>(data[1]);
              AppendToBuffer("%s %s,%s,%d", pseudo_op[op - 0x08],
                             NameOfXMMRegister(regop), NameOfXMMRegister(rm),
                             static_cast<int>(imm8));
              data += 2;
            } else if (*data == 0x0E) {
              data++;
              int mod, regop, rm;
              get_modrm(*data, &mod, &regop, &rm);
              AppendToBuffer("pblendw %s,", NameOfXMMRegister(regop));
              data += PrintRightXMMOperand(data);
              AppendToBuffer(",%d", Imm8_U(data));
              data++;
            } else if (*data == 0x0F) {
              data++;
              int mod, regop, rm;
              get_modrm(*data, &mod, &regop, &rm);
              AppendToBuffer("palignr %s,", NameOfXMMRegister(regop));
              data += PrintRightXMMOperand(data);
              AppendToBuffer(",%d", Imm8_U(data));
              data++;
            } else if (*data == 0x14) {
              data++;
              int mod, regop, rm;
              get_modrm(*data, &mod, &regop, &rm);
              AppendToBuffer("pextrb ");
              data += PrintRightOperand(data);
              AppendToBuffer(",%s,%d", NameOfXMMRegister(regop), Imm8(data));
              data++;
            } else if (*data == 0x15) {
              data++;
              int mod, regop, rm;
              get_modrm(*data, &mod, &regop, &rm);
              AppendToBuffer("pextrw ");
              data += PrintRightOperand(data);
              AppendToBuffer(",%s,%d", NameOfXMMRegister(regop), Imm8(data));
              data++;
            } else if (*data == 0x16) {
              data++;
              int mod, regop, rm;
              get_modrm(*data, &mod, &regop, &rm);
              AppendToBuffer("pextrd ");
              data += PrintRightOperand(data);
              AppendToBuffer(",%s,%d", NameOfXMMRegister(regop), Imm8(data));
              data++;
            } else if (*data == 0x17) {
              data++;
              int mod, regop, rm;
              get_modrm(*data, &mod, &regop, &rm);
              int8_t imm8 = static_cast<int8_t>(data[1]);
              AppendToBuffer("extractps %s,%s,%d", NameOfCPURegister(rm),
                             NameOfXMMRegister(regop), static_cast<int>(imm8));
              data += 2;
            } else if (*data == 0x20) {
              data++;
              int mod, regop, rm;
              get_modrm(*data, &mod, &regop, &rm);
              AppendToBuffer("pinsrb %s,", NameOfXMMRegister(regop));
              data += PrintRightOperand(data);
              AppendToBuffer(",%d", Imm8(data));
              data++;
            } else if (*data == 0x21) {
              data++;
              int mod, regop, rm;
              get_modrm(*data, &mod, &regop, &rm);
              AppendToBuffer("insertps %s,", NameOfXMMRegister(regop));
              data += PrintRightXMMOperand(data);
              AppendToBuffer(",%d", Imm8(data));
              data++;
            } else if (*data == 0x22) {
              data++;
              int mod, regop, rm;
              get_modrm(*data, &mod, &regop, &rm);
              AppendToBuffer("pinsrd %s,", NameOfXMMRegister(regop));
              data += PrintRightOperand(data);
              AppendToBuffer(",%d", Imm8(data));
              data++;
            } else {
              UnimplementedInstruction();
            }
          } else if (*data == 0x2E || *data == 0x2F) {
            const char* mnem = (*data == 0x2E) ? "ucomisd" : "comisd";
            data++;
            int mod, regop, rm;
            get_modrm(*data, &mod, &regop, &rm);
            if (mod == 0x3) {
              AppendToBuffer("%s %s,%s", mnem, NameOfXMMRegister(regop),
                             NameOfXMMRegister(rm));
              data++;
            } else {
              AppendToBuffer("%s %s,", mnem, NameOfXMMRegister(regop));
              data += PrintRightOperand(data);
            }
          } else if (*data == 0x50) {
            data++;
            int mod, regop, rm;
            get_modrm(*data, &mod, &regop, &rm);
            AppendToBuffer("movmskpd %s,%s", NameOfCPURegister(regop),
                           NameOfXMMRegister(rm));
            data++;
          } else if (*data >= 0x54 && *data <= 0x5A) {
            const char* const pseudo_op[] = {"andpd",   "andnpd", "orpd",
                                             "xorpd",   "addpd",  "mulpd",
                                             "cvtpd2ps"};
            uint8_t op = *data;
            data++;
            int mod, regop, rm;
            get_modrm(*data, &mod, &regop, &rm);
            AppendToBuffer("%s %s,", pseudo_op[op - 0x54],
                           NameOfXMMRegister(regop));
            data += PrintRightXMMOperand(data);
          } else if (*data >= 0x5c && *data <= 0x5f) {
            const char* const pseudo_op[] = {
                "subpd",
                "minpd",
                "divpd",
                "maxpd",
            };
            uint8_t op = *data;
            data++;
            int mod, regop, rm;
            get_modrm(*data, &mod, &regop, &rm);
            AppendToBuffer("%s %s,", pseudo_op[op - 0x5c],
                           NameOfXMMRegister(regop));
            data += PrintRightXMMOperand(data);
          } else if (*data == 0x6E) {
            data++;
            int mod, regop, rm;
            get_modrm(*data, &mod, &regop, &rm);
            AppendToBuffer("movd %s,", NameOfXMMRegister(regop));
            data += PrintRightOperand(data);
          } else if (*data == 0x6F) {
            data++;
            int mod, regop, rm;
            get_modrm(*data, &mod, &regop, &rm);
            AppendToBuffer("movdqa %s,", NameOfXMMRegister(regop));
            data += PrintRightXMMOperand(data);
          } else if (*data == 0x70) {
            data++;
            int mod, regop, rm;
            get_modrm(*data, &mod, &regop, &rm);
            AppendToBuffer("pshufd %s,", NameOfXMMRegister(regop));
            data += PrintRightXMMOperand(data);
            AppendToBuffer(",%d", Imm8(data));
            data++;
          } else if (*data == 0x90) {
            data++;
            AppendToBuffer("nop");  // 2 byte nop.
          } else if (*data == 0x71) {
            data++;
            int mod, regop, rm;
            get_modrm(*data, &mod, &regop, &rm);
            int8_t imm8 = static_cast<int8_t>(data[1]);
            AppendToBuffer("ps%sw %s,%d", sf_str[regop / 2],
                           NameOfXMMRegister(rm), static_cast<int>(imm8));
            data += 2;
          } else if (*data == 0x72) {
            data++;
            int mod, regop, rm;
            get_modrm(*data, &mod, &regop, &rm);
            int8_t imm8 = static_cast<int8_t>(data[1]);
            AppendToBuffer("ps%sd %s,%d", sf_str[regop / 2],
                           NameOfXMMRegister(rm), static_cast<int>(imm8));
            data += 2;
          } else if (*data == 0x73) {
            data++;
            int mod, regop, rm;
            get_modrm(*data, &mod, &regop, &rm);
            int8_t imm8 = static_cast<int8_t>(data[1]);
            DCHECK(regop == esi || regop == edx);
            AppendToBuffer("ps%sq %s,%d", sf_str[regop / 2],
                           NameOfXMMRegister(rm), static_cast<int>(imm8));
            data += 2;
          } else if (*data == 0x7F) {
            AppendToBuffer("movdqa ");
            data++;
            int mod, regop, rm;
            get_modrm(*data, &mod, &regop, &rm);
            data += PrintRightXMMOperand(data);
            AppendToBuffer(",%s", NameOfXMMRegister(regop));
          } else if (*data == 0x7E) {
            data++;
            int mod, regop, rm;
            get_modrm(*data, &mod, &regop, &rm);
            AppendToBuffer("movd ");
            data += PrintRightOperand(data);
            AppendToBuffer(",%s", NameOfXMMRegister(regop));
          } else if (*data == 0xC1) {
            data += 2;
            data += PrintOperands("xadd_w", OPER_REG_OP_ORDER, data);
          } else if (*data == 0xC2) {
            data++;
            int mod, regop, rm;
            get_modrm(*data, &mod, &regop, &rm);
            AppendToBuffer("cmppd %s, ", NameOfXMMRegister(regop));
            data += PrintRightXMMOperand(data);
            AppendToBuffer(", (%s)", cmp_pseudo_op[*data]);
            data++;
          } else if (*data == 0xC4) {
            data++;
            int mod, regop, rm;
            get_modrm(*data, &mod, &regop, &rm);
            AppendToBuffer("pinsrw %s,", NameOfXMMRegister(regop));
            data += PrintRightOperand(data);
            AppendToBuffer(",%d", Imm8(data));
            data++;
          } else if (*data == 0xC6) {
            // shufpd xmm, xmm/m128, imm8
            data++;
            int mod, regop, rm;
            get_modrm(*data, &mod, &regop, &rm);
            AppendToBuffer("shufpd %s,", NameOfXMMRegister(regop));
            data += PrintRightXMMOperand(data);
            AppendToBuffer(",%d", Imm8(data));
            data++;
          } else if (*data == 0xE6) {
            data++;
            int mod, regop, rm;
            get_modrm(*data, &mod, &regop, &rm);
            AppendToBuffer("cvttpd2dq %s,", NameOfXMMRegister(regop));
            data += PrintRightXMMOperand(data);
          } else if (*data == 0xE7) {
            data++;
            int mod, regop, rm;
            get_modrm(*data, &mod, &regop, &rm);
            if (mod == 3) {
              // movntdq
              UnimplementedInstruction();
            } else {
              UnimplementedInstruction();
            }
          } else if (*data == 0xB1) {
            data++;
            data += PrintOperands("cmpxchg_w", OPER_REG_OP_ORDER, data);
          } else if (*data == 0xD7) {
            data++;
            int mod, regop, rm;
            get_modrm(*data, &mod, &regop, &rm);
            AppendToBuffer("pmovmskb %s,%s", NameOfCPURegister(regop),
                           NameOfXMMRegister(rm));
            data++;
          } else {
            uint8_t op = *data;
            data++;
            int mod, regop, rm;
            get_modrm(*data, &mod, &regop, &rm);
            switch (op) {
#define SSE2_DIS_CASE(instruction, notUsed1, notUsed2, opcode)     \
  case 0x##opcode: {                                               \
    AppendToBuffer(#instruction " %s,", NameOfXMMRegister(regop)); \
    data += PrintRightXMMOperand(data);                            \
    break;                                                         \
  }

              SSE2_INSTRUCTION_LIST(SSE2_DIS_CASE)
#undef SSE2_DIS_CASE
              default:
                UnimplementedInstruction();
            }
          }
        } else {
          UnimplementedInstruction();
        }
        break;

      case 0xFE: {
        data++;
        int mod, regop, rm;
        get_modrm(*data, &mod, &regop, &rm);
        if (regop == ecx) {
          AppendToBuffer("dec_b ");
          data += PrintRightOperand(data);
        } else {
          UnimplementedInstruction();
        }
      } break;

      case 0x68:
        AppendToBuffer("push 0x%x", Imm32(data + 1));
        data += 5;
        break;

      case 0x6A:
        AppendToBuffer("push 0x%x", Imm8(data + 1));
        data += 2;
        break;

      case 0xA8:
        AppendToBuffer("test al,0x%x", Imm8_U(data + 1));
        data += 2;
        break;

      case 0xA9:
        AppendToBuffer("test eax,0x%x", Imm32(data + 1));
        data += 5;
        break;

      case 0xD1:  // fall through
      case 0xD3:  // fall through
      case 0xC1:
        data += D1D3C1Instruction(data);
        break;

      case 0xD8:  // fall through
      case 0xD9:  // fall through
      case 0xDA:  // fall through
      case 0xDB:  // fall through
      case 0xDC:  // fall through
      case 0xDD:  // fall through
      case 0xDE:  // fall through
      case 0xDF:
        data += FPUInstruction(data);
        break;

      case 0xEB:
        data += JumpShort(data);
        break;

      case 0xF2:
        if (*(data + 1) == 0x0F) {
          uint8_t b2 = *(data + 2);
          if (b2 == 0x11) {
            AppendToBuffer("movsd ");
            data += 3;
            int mod, regop, rm;
            get_modrm(*data, &mod, &regop, &rm);
            data += PrintRightXMMOperand(data);
            AppendToBuffer(",%s", NameOfXMMRegister(regop));
          } else if (b2 == 0x10) {
            data += 3;
            int mod, regop, rm;
            get_modrm(*data, &mod, &regop, &rm);
            AppendToBuffer("movsd %s,", NameOfXMMRegister(regop));
            data += PrintRightXMMOperand(data);
          } else if (b2 == 0x12) {
            data += 3;
            int mod, regop, rm;
            get_modrm(*data, &mod, &regop, &rm);
            AppendToBuffer("movddup %s,", NameOfXMMRegister(regop));
            data += PrintRightXMMOperand(data);
          } else if (b2 == 0x5A) {
            data += 3;
            int mod, regop, rm;
            get_modrm(*data, &mod, &regop, &rm);
            AppendToBuffer("cvtsd2ss %s,", NameOfXMMRegister(regop));
            data += PrintRightXMMOperand(data);
          } else if (b2 == 0x70) {
            data += 3;
            int mod, regop, rm;
            get_modrm(*data, &mod, &regop, &rm);
            AppendToBuffer("pshuflw %s,", NameOfXMMRegister(regop));
            data += PrintRightXMMOperand(data);
            AppendToBuffer(",%d", Imm8(data));
            data++;
          } else {
            const char* mnem = "?";
            switch (b2) {
              case 0x2A:
                mnem = "cvtsi2sd";
                break;
              case 0x2C:
                mnem = "cvttsd2si";
                break;
              case 0x2D:
                mnem = "cvtsd2si";
                break;
              case 0x7C:
                mnem = "haddps";
                break;
#define MNEM_FOR_SSE2_INSTRUCTION_LSIT_SD(instruction, _1, _2, opcode) \
  case 0x##opcode:                                                     \
    mnem = "" #instruction;                                            \
    break;
                SSE2_INSTRUCTION_LIST_SD(MNEM_FOR_SSE2_INSTRUCTION_LSIT_SD)
#undef MNEM_FOR_SSE2_INSTRUCTION_LSIT_SD
            }
            data += 3;
            int mod, regop, rm;
            get_modrm(*data, &mod, &regop, &rm);
            if (b2 == 0x2A) {
              AppendToBuffer("%s %s,", mnem, NameOfXMMRegister(regop));
              data += PrintRightOperand(data);
            } else if (b2 == 0x2C || b2 == 0x2D) {
              AppendToBuffer("%s %s,", mnem, NameOfCPURegister(regop));
              data += PrintRightXMMOperand(data);
            } else if (b2 == 0xC2) {
              // Intel manual 2A, Table 3-18.
              AppendToBuffer("cmp%ssd %s,%s", cmp_pseudo_op[data[1]],
                             NameOfXMMRegister(regop), NameOfXMMRegister(rm));
              data += 2;
            } else {
              AppendToBuffer("%s %s,", mnem, NameOfXMMRegister(regop));
              data += PrintRightXMMOperand(data);
            }
          }
        } else {
          UnimplementedInstruction();
          data++;
        }
        break;

      case 0xF3:
        if (*(data + 1) == 0x0F) {
          uint8_t b2 = *(data + 2);
          if (b2 == 0x11) {
            AppendToBuffer("movss ");
            data += 3;
            int mod, regop, rm;
            get_modrm(*data, &mod, &regop, &rm);
            data += PrintRightXMMOperand(data);
            AppendToBuffer(",%s", NameOfXMMRegister(regop));
          } else if (b2 == 0x10) {
            data += 3;
            int mod, regop, rm;
            get_modrm(*data, &mod, &regop, &rm);
            AppendToBuffer("movss %s,", NameOfXMMRegister(regop));
            data += PrintRightXMMOperand(data);
          } else if (b2 == 0x16) {
            data += 3;
            int mod, regop, rm;
            get_modrm(*data, &mod, &regop, &rm);
            AppendToBuffer("movshdup %s,", NameOfXMMRegister(regop));
            data += PrintRightXMMOperand(data);
          } else if (b2 == 0x5A) {
            data += 3;
            int mod, regop, rm;
            get_modrm(*data, &mod, &regop, &rm);
            AppendToBuffer("cvtss2sd %s,", NameOfXMMRegister(regop));
            data += PrintRightXMMOperand(data);
          } else if (b2 == 0x6F) {
            data += 3;
            int mod, regop, rm;
            get_modrm(*data, &mod, &regop, &rm);
            AppendToBuffer("movdqu %s,", NameOfXMMRegister(regop));
            data += PrintRightXMMOperand(data);
          } else if (b2 == 0x70) {
            data += 3;
            int mod, regop, rm;
            get_modrm(*data, &mod, &regop, &rm);
            AppendToBuffer("pshufhw %s,", NameOfXMMRegister(regop));
            data += PrintRightXMMOperand(data);
            AppendToBuffer(",%d", Imm8(data));
            data++;
          } else if (b2 == 0x7F) {
            AppendToBuffer("movdqu ");
            data += 3;
            int mod, regop, rm;
            get_modrm(*data, &mod, &regop, &rm);
            data += PrintRightXMMOperand(data);
            AppendToBuffer(",%s", NameOfXMMRegister(regop));
          } else if (b2 == 0xB8) {
            data += 3;
            int mod, regop, rm;
            get_modrm(*data, &mod, &regop, &rm);
            AppendToBuffer("popcnt %s,", NameOfCPURegister(regop));
            data += PrintRightOperand(data);
          } else if (b2 == 0xBC) {
            data += 3;
            int mod, regop, rm;
            get_modrm(*data, &mod, &regop, &rm);
            AppendToBuffer("tzcnt %s,", NameOfCPURegister(regop));
            data += PrintRightOperand(data);
          } else if (b2 == 0xBD) {
            data += 3;
            int mod, regop, rm;
            get_modrm(*data, &mod, &regop, &rm);
            AppendToBuffer("lzcnt %s,", NameOfCPURegister(regop));
            data += PrintRightOperand(data);
          } else if (b2 == 0xE6) {
            data += 3;
            int mod, regop, rm;
            get_modrm(*data, &mod, &regop, &rm);
            AppendToBuffer("cvtdq2pd %s", NameOfXMMRegister(regop));
            data += PrintRightXMMOperand(data);
          } else {
            const char* mnem = "?";
            switch (b2) {
              case 0x2A:
                mnem = "cvtsi2ss";
                break;
              case 0x2C:
                mnem = "cvttss2si";
                break;
              case 0x2D:
                mnem = "cvtss2si";
                break;
              case 0x51:
                mnem = "sqrtss";
                break;
              case 0x58:
                mnem = "addss";
                break;
              case 0x59:
                mnem = "mulss";
                break;
              case 0x5B:
                mnem = "cvttps2dq";
                break;
              case 0x5C:
                mnem = "subss";
                break;
              case 0x5D:
                mnem = "minss";
                break;
              case 0x5E:
                mnem = "divss";
                break;
              case 0x5F:
                mnem = "maxss";
                break;
              case 0x7E:
                mnem = "movq";
                break;
            }
            data += 3;
            int mod, regop, rm;
            get_modrm(*data, &mod, &regop, &rm);
            if (b2 == 0x2A) {
              AppendToBuffer("%s %s,", mnem, NameOfXMMRegister(regop));
              data += PrintRightOperand(data);
            } else if (b2 == 0x2C || b2 == 0x2D) {
              AppendToBuffer("%s %s,", mnem, NameOfCPURegister(regop));
              data += PrintRightXMMOperand(data);
            } else if (b2 == 0xC2) {
              // Intel manual 2A, Table 3-18.
              AppendToBuffer("cmp%sss %s,%s", cmp_pseudo_op[data[1]],
                             NameOfXMMRegister(regop), NameOfXMMRegister(rm));
              data += 2;
            } else {
              AppendToBuffer("%s %s,", mnem, NameOfXMMRegister(regop));
              data += PrintRightXMMOperand(data);
            }
          }
        } else if (*(data + 1) == 0xA5) {
          data += 2;
          AppendToBuffer("rep_movs");
        } else if (*(data + 1) == 0xAB) {
          data += 2;
          AppendToBuffer("rep_stos");
        } else if (*(data + 1) == 0x90) {
          data += 2;
          AppendToBuffer("pause");
        } else {
          UnimplementedInstruction();
        }
        break;

      case 0xF7:
        data += F7Instruction(data);
        break;

      default:
        UnimplementedInstruction();
        data++;
    }
  }

  if (tmp_buffer_pos_ < sizeof tmp_buffer_) {
    tmp_buffer_[tmp_buffer_pos_] = '\0';
  }

  int instr_len = data - instr;
  if (instr_len == 0) {
    printf("%02x", *data);
  }
  DCHECK_GT(instr_len, 0);  // Ensure progress.

  int outp = 0;
  // Instruction bytes.
  for (uint8_t* bp = instr; bp < data; bp++) {
    outp += v8::base::SNPrintF(out_buffer + outp, "%02x", *bp);
  }
  // Indent instruction, leaving space for 6 bytes, i.e. 12 characters in hex.
  while (outp < 12) {
    outp += v8::base::SNPrintF(out_buffer + outp, "  ");
  }

  outp += v8::base::SNPrintF(out_buffer + outp, " %s", tmp_buffer_.begin());
  return instr_len;
}

//------------------------------------------------------------------------------

static const char* const cpu_regs[8] = {"eax", "ecx", "edx", "ebx",
                                        "esp", "ebp", "esi", "edi"};

static const char* const byte_cpu_regs[8] = {"al", "cl", "dl", "bl",
                                             "ah", "ch", "dh", "bh"};

static const char* const xmm_regs[8] = {"xmm0", "xmm1", "xmm2", "xmm3",
                                        "xmm4", "xmm5", "xmm6", "xmm7"};

const char* NameConverter::NameOfAddress(uint8_t* addr) const {
  v8::base::SNPrintF(tmp_buffer_, "%p", static_cast<void*>(addr));
  return tmp_buffer_.begin();
}

const char* NameConverter::NameOfConstant(uint8_t* addr) const {
  return NameOfAddress(addr);
}

const char* NameConverter::NameOfCPURegister(int reg) const {
  if (0 <= reg && reg < 8) return cpu_regs[reg];
  return "noreg";
}

const char* NameConverter::NameOfByteCPURegister(int reg) const {
  if (0 <= reg && reg < 8) return byte_cpu_regs[reg];
  return "noreg";
}

const char* NameConverter::NameOfXMMRegister(int reg) const {
  if (0 <= reg && reg < 8) return xmm_regs[reg];
  return "noxmmreg";
}

const char* NameConverter::NameInCode(uint8_t* addr) const {
  // IA32 does not embed debug strings at the moment.
  UNREACHABLE();
}

//------------------------------------------------------------------------------

int Disassembler::InstructionDecode(v8::base::Vector<char> buffer,
                                    uint8_t* instruction) {
  DisassemblerIA32 d(converter_, unimplemented_opcode_action());
  return d.InstructionDecode(buffer, instruction);
}

// The IA-32 assembler does not currently use constant pools.
int Disassembler::ConstantPoolSizeAt(uint8_t* instruction) { return -1; }

// static
void Disassembler::Disassemble(FILE* f, uint8_t* begin, uint8_t* end,
                               UnimplementedOpcodeAction unimplemented_action) {
  NameConverter converter;
  Disassembler d(converter, unimplemented_action);
  for (uint8_t* pc = begin; pc < end;) {
    v8::base::EmbeddedVector<char, 128> buffer;
    buffer[0] = '\0';
    uint8_t* prev_pc = pc;
    pc += d.InstructionDecode(buffer, pc);
    fprintf(f, "%p", static_cast<void*>(prev_pc));
    fprintf(f, "    ");

    for (uint8_t* bp = prev_pc; bp < pc; bp++) {
      fprintf(f, "%02x", *bp);
    }
    for (int i = 6 - (pc - prev_pc); i >= 0; i--) {
      fprintf(f, "  ");
    }
    fprintf(f, "  %s\n", buffer.begin());
  }
}

}  // namespace disasm

#endif  // V8_TARGET_ARCH_IA32
```