Response:
The user wants a summary of the provided C++ code snippet. This code is a part of the V8 JavaScript engine and is responsible for disassembling x64 machine code instructions.

Here's a breakdown of the request and how to address it:

1. **Identify the Core Functionality:** The code is clearly about disassembling x64 instructions. This involves reading byte sequences representing instructions and converting them into a human-readable text format (assembly language).

2. **Check for Torque Source:** The prompt explicitly asks if the file could be a Torque source if it ended in `.tq`. This is not the case here, as the filename ends in `.cc`.

3. **Relate to JavaScript (if applicable):**  Disassemblers are indirectly related to JavaScript. When the V8 engine executes JavaScript code, it compiles it into machine code. This disassembler is used for debugging and analysis of that generated machine code. A simple example would be demonstrating a JavaScript function and how the disassembler helps understand its low-level representation.

4. **Demonstrate Code Logic (with assumptions):** The code has a lot of `switch` statements based on opcodes and prefixes. To illustrate this, we can pick a specific instruction sequence, assume it as input, and trace the code to show the output (the disassembled instruction).

5. **Highlight Common Programming Errors (if applicable):** While this code itself is unlikely to cause *user* programming errors, we can point out how a *user* might encounter issues related to the disassembled output, such as misinterpreting assembly instructions or not understanding how JavaScript translates to machine code.

6. **Summarize Functionality:**  Finally, provide a concise summary of the code's purpose.

**Plan:**

* **State the primary function:** Disassembling x64 instructions.
* **Confirm it's not Torque:** Based on the `.cc` extension.
* **JavaScript Relation:** Explain that it helps understand the low-level implementation of JavaScript. Give a simple JavaScript function example and mention how the disassembler would show the corresponding machine code (without actually running the disassembler, just conceptually).
* **Code Logic Example:** Choose a simple AVX instruction from the provided code (e.g., `vpermq`). Assume a byte sequence for this instruction and show how the code would process it to generate the disassembled string.
* **Common Errors:** Explain that users might struggle to interpret the disassembled output without knowledge of assembly language or the underlying architecture.
* **Concise Summary:** Reiterate the core function of the code.
这是目录为v8/src/diagnostics/x64/disasm-x64.cc的V8源代码的一部分，它专注于反汇编（disassemble）x64架构的指令。该部分代码主要处理VEX编码的指令以及部分传统的SSE和FPU指令。

**功能归纳:**

这段代码的主要功能是**将x64架构的机器码（字节序列）翻译成人类可读的汇编指令字符串**。  它特别关注以下方面：

* **处理VEX前缀指令:**  VEX前缀是AVX和AVX-512指令集的编码方式。代码中大量的`if (vex_...)` 条件分支表明它正在解析带有VEX前缀的指令。
* **反汇编各种SIMD指令:** 代码中出现了大量的以 "v" 开头的指令，如 `vpermq`, `vroundps`, `vmovss`, `vaddpd` 等，这些都是SIMD (Single Instruction, Multiple Data) 指令，主要用于并行处理数据。 这包括 FMA (Fused Multiply-Add) 指令。
* **处理不同的VEX编码形式:** 代码通过 `vex_66()`, `vex_0f()`, `vex_0f38()`, `vex_0f3a()` 等函数来判断VEX前缀的不同形式，并根据不同的形式解析相应的指令。
* **处理部分传统的SSE指令:** 代码中也包含对不带VEX前缀的SSE (Streaming SIMD Extensions) 指令的反汇编，例如 `movups`, `movapd`, `ucomiss` 等。
* **处理部分FPU指令:** 代码末尾包含了对传统x87浮点单元 (FPU) 指令的反汇编，如 `fld`, `fstp`, `fadd`, `fmul` 等。
* **格式化输出:**  代码使用 `AppendToBuffer` 函数将反汇编后的指令及其操作数格式化成字符串。
* **处理ModR/M字节:** 代码中多次调用 `get_modrm` 函数，这表明它正在解析ModR/M字节，该字节用于确定指令的操作数是寄存器还是内存地址。

**如果 v8/src/diagnostics/x64/disasm-x64.cc 以 .tq 结尾，那它是个 v8 torque 源代码:**

根据您提供的规则，如果文件以 `.tq` 结尾，那么它将被视为 V8 Torque 源代码。 Torque 是一种用于编写 V8 内部代码的高级类型化语言。然而，根据您提供的文件名 `v8/src/diagnostics/x64/disasm-x64.cc`，它是一个 C++ 源代码文件。

**如果它与 javascript 的功能有关系，请用 javascript 举例说明:**

`v8/src/diagnostics/x64/disasm-x64.cc` 与 JavaScript 的功能有密切关系，因为它用于调试和分析 V8 执行 JavaScript 代码时生成的机器码。

**JavaScript 示例:**

```javascript
function add(a, b) {
  return a + b;
}

add(5, 10);
```

当 V8 执行这段 JavaScript 代码时，它会将 `add` 函数编译成 x64 机器码。 `disasm-x64.cc` 中的代码可以用来查看生成的机器码指令，例如可能会看到类似于以下的指令（这只是一个简化的例子，实际生成的代码会更复杂）：

```assembly
mov     eax, [rsp+0x8]  ; 将参数 a 从栈中加载到 eax 寄存器
add     eax, [rsp+0x10] ; 将参数 b 从栈中加载到 eax 寄存器并与 eax 相加
ret                     ; 返回结果
```

`disasm-x64.cc` 的功能就是将上面这样的机器码字节翻译成 `mov eax, [rsp+0x8]` 这样的可读汇编指令。这对于理解 V8 如何执行 JavaScript 代码，以及优化性能非常有用。

**如果有代码逻辑推理，请给出假设输入与输出:**

假设输入的字节序列是 `0xC5`, `0xFB`, `0x10`, `0x05`, `0x34`, `0x12`, `0x00`, `0x00`。  根据代码逻辑，可以推断出这是一个 VEX 编码的 `vaddpd` 指令。

* **`0xC5`**:  表示这是一个双字节 VEX 前缀。
* **`0xFB`**:  包含 VEX 寄存器信息、操作码映射以及 W 位。
* **`0x10`**:  是实际的操作码，对于 `vaddpd` 来说是 `0x10`。
* **`0x05`**:  是 ModR/M 字节，假设它指向一个内存地址。
* **`0x34`, `0x12`, `0x00`, `0x00`**:  是内存地址的偏移量（假设是 32 位）。

**推断过程:**

1. 代码会首先识别出 `0xC5`，确定存在 VEX 前缀。
2. 解析 `0xFB`，提取出必要的编码信息。
3. 根据操作码 `0x10`，并在 `vex_66()` 和 `vex_0f()` 都为真的条件下，进入对应的 `case 0x10:` 分支。
4. 由于 ModR/M 字节 `0x05` 的 `mod` 位不为 `0b11`，代码会将其识别为内存操作数。
5. `PrintRightAVXOperand` 函数会根据 ModR/M 字节和后续的偏移量，格式化内存操作数。

**假设输出:**

```assembly
vaddpd xmm0,[rip+0x1234]
```

（实际输出会依赖于 `NameOfAVXRegister(regop)` 和 `PrintRightAVXOperand` 的具体实现，以及假设的 ModR/M 和偏移量。）

**如果涉及用户常见的编程错误，请举例说明:**

这段代码本身是 V8 引擎的内部代码，不太涉及用户的直接编程错误。但是，如果用户尝试直接解析或理解这段反汇编代码，可能会遇到以下常见的理解错误：

1. **不理解汇编指令的含义:**  用户可能不熟悉 x64 汇编语言，无法理解 `vpermq`, `vroundps` 等指令的作用，以及它们的操作数。
2. **误解寄存器的用途:**  用户可能不清楚 `xmm` 寄存器、通用寄存器（如 `eax`）以及控制寄存器等的用途和区别。
3. **忽略指令前缀的影响:** 用户可能忽略了 VEX 前缀对指令行为的影响，例如它如何扩展寄存器数量和提供更灵活的寻址方式。
4. **不熟悉内存寻址模式:**  用户可能不理解 ModR/M 字节如何编码不同的内存寻址模式，例如直接寻址、寄存器间接寻址、基址加偏移寻址等。
5. **将反汇编代码等同于源代码:**  用户可能错误地认为反汇编代码就是原始的 JavaScript 源代码，而忽略了编译和优化的过程。

**总结其功能 (针对第 2 部分):**

这部分 `disasm-x64.cc` 代码负责反汇编大量的 **VEX 编码的 SIMD 指令 (包括 AVX 和 FMA)** 以及部分 **传统的 SSE 和 FPU 指令**。它通过解析指令的操作码、前缀以及 ModR/M 字节等信息，将机器码转换为可读的汇编指令字符串，这对于理解 V8 引擎执行 JavaScript 代码的底层机制至关重要。

### 提示词
```
这是目录为v8/src/diagnostics/x64/disasm-x64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/diagnostics/x64/disasm-x64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
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