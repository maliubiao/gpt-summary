Response:
The user wants to understand the functionality of the provided C++ code snippet, which is part of V8's disassembler for the RISC-V architecture.

Here's a breakdown of the thought process to answer the request:

1. **Identify the Core Function:** The code is a part of a `Decoder` class in `v8/src/diagnostics/riscv/disasm-riscv.cc`. The name "disasm-riscv" strongly suggests it's responsible for disassembling RISC-V instructions. The methods like `DecodeRType`, `DecodeIType`, etc., further confirm this, indicating they handle decoding and formatting different RISC-V instruction types.

2. **Explain the Purpose:**  The primary function is to take a raw RISC-V instruction (represented by its bit pattern) and translate it into a human-readable assembly language representation. This is crucial for debugging, reverse engineering, and understanding the low-level behavior of code.

3. **Address the ".tq" Question:** The question about the `.tq` extension is a bit of a red herring based on the provided C++ code. Torque is a different language used in V8 for runtime code generation. Since the provided code is `.cc`, it's C++. State this clearly and explain the difference.

4. **Relate to JavaScript (if applicable):**  Disassemblers don't directly execute JavaScript. However, they are essential tools *for the V8 engine*, which executes JavaScript. Explain this indirect relationship:  When V8 compiles JavaScript, it generates machine code. The disassembler helps developers (and V8 developers) inspect this generated code. A simple example would be how a JavaScript function might be compiled into RISC-V instructions, which the disassembler can then reveal.

5. **Code Logic and Examples:**  Choose a representative code block to illustrate the logic. The `DecodeRType` function is a good example.
    * **Assumption:** An `Instruction* instr` object containing the bit representation of a RISC-V R-type instruction.
    * **Input:** A hypothetical RISC-V instruction bit pattern (e.g., for `add`).
    * **Output:** The formatted assembly string (e.g., "add rd, rs1, rs2").
    * Explain how the code uses bitmasking and switch statements to identify the specific instruction and format the output.

6. **Common Programming Errors:** Think about the context of *using* a disassembler or working with assembly. Common errors include:
    * Misinterpreting disassembled output.
    * Incorrectly assuming the disassembled code is exactly what was intended (compilers optimize).
    * Not understanding the nuances of the target architecture (RISC-V in this case).
    * Errors in manually writing assembly code (which could be revealed by a disassembler).

7. **Summarize the Functionality (for Part 2):** Focus on the core task: decoding and formatting RISC-V instructions based on their type. Highlight the use of bit manipulation and lookups to achieve this.

8. **Structure the Answer:** Organize the information logically with clear headings to address each part of the user's request. Use code formatting and clear language.

**Self-Correction/Refinement during thought process:**

* Initially, I might have focused too much on the details of each instruction. Realized that a higher-level explanation of the overall purpose is more important for the user's understanding.
* Considered whether to provide specific RISC-V instruction encodings as examples. Decided against it to keep the explanation simpler and focused on the disassembler's function, not RISC-V instruction set details.
* Double-checked the relationship between the disassembler and JavaScript execution to ensure the explanation is accurate and clear about the indirect connection.
* Made sure to clearly distinguish between C++ and Torque.
好的，根据提供的代码片段，我们可以归纳一下 `v8/src/diagnostics/riscv/disasm-riscv.cc` 的部分功能：

**核心功能：RISC-V 指令的解码和格式化**

这段代码的主要职责是解码 RISC-V 架构的机器指令，并将其格式化为人类可读的汇编语言表示形式。它通过分析指令的二进制位模式，识别出具体的指令类型和操作，然后使用预定义的格式字符串生成相应的汇编代码。

**具体功能点 (基于提供的代码片段)：**

1. **处理原子操作 (A 扩展):** `DecodeRAType` 函数专门用于处理 RISC-V 原子扩展指令，例如 `lr.w` (Load Reserved Word), `sc.w` (Store Conditional Word), `amoswap.w` (Atomic Memory Operation Swap Word) 等。它根据指令的不同位域 (特别是 `kRATypeMask`) 来确定具体的原子操作，并使用 `Format` 函数生成相应的汇编代码字符串，例如 `lr.w'a    'rd, ('rs1')`。

2. **处理浮点操作 (F/D 扩展):** `DecodeRFPType` 函数负责解码和格式化 RISC-V 浮点指令，包括单精度 (F) 和双精度 (D) 浮点运算。它通过 `kRFPTypeMask` 来识别不同的浮点指令，并根据 `Funct3Value` 和 `Rs2Value` 等进一步区分同一大类下的不同操作，例如 `fadd.s` (浮点加法单精度), `fsub.d` (浮点减法双精度) 等。对于一些特殊的指令，例如 `fsgnj.s` (浮点符号注入)，还会根据 `Funct3Value` 的不同值生成不同的伪指令，例如当 `Rs1Value` 等于 `Rs2Value` 时，`fsgnj.s` 可以被格式化为 `fmv.s` (浮点移动)。

3. **处理浮点混合乘加/减操作 (涉及四个操作数的指令):** `DecodeR4Type` 函数处理需要四个操作数的浮点指令，例如 `fmadd.s` (浮点乘加单精度), `fmsub.d` (浮点乘减双精度) 等。

4. **处理 I 型指令:** `DecodeIType` 函数解码 RISC-V 的 I 型指令，这类指令通常包含一个立即数。它涵盖了多种操作，包括：
   - **跳转和链接寄存器 (JALR):**  处理 `jalr` 指令，并根据不同的寄存器和立即数值生成 `ret`, `jr`, `jalr` 或完整的 `jalr` 指令格式。
   - **加载指令:** 处理各种加载指令，例如 `lb` (加载字节), `lh` (加载半字), `lw` (加载字), `ld` (加载双字 - 仅限 64 位架构) 等。
   - **算术立即数指令:** 处理带立即数的算术运算，例如 `addi` (加立即数), `slti` (小于置位立即数), `xori` (异或立即数) 等。对于一些特殊情况，例如 `addi` 立即数为 0 时，会格式化为 `mv` (移动) 或 `nop` (空操作)。
   - **移位立即数指令:** 处理移位立即数指令，例如 `slli` (逻辑左移立即数), `srli` (逻辑右移立即数), `srai` (算术右移立即数)。还包括一些位操作指令，如 `bclri`, `bseti`, `binvi`, 以及一些扩展指令如 `clz`, `ctz`, `cpop`, `sext.b`, `sext.h`.
   - **FENCE 指令:** 处理内存屏障指令。
   - **ECALL 和 EBREAK 指令:** 处理系统调用和断点指令。
   - **CSR (Control and Status Register) 操作指令:** 处理读写控制状态寄存器的指令，例如 `csrrs`, `csrrw`, `csrrc` 等。对于一些常用的 CSR 寄存器，例如 `fcsr`, `frm`, `fflags`, `instret`, `time`, `cycle` 等，会生成更友好的助记符，例如 `fscsr`, `fsrm`, `rdinstret` 等。
   - **浮点加载指令:** 处理浮点加载指令，例如 `flw` (加载浮点字), `fld` (加载浮点双字)。

5. **处理 S 型指令:** `DecodeSType` 函数解码 RISC-V 的 S 型指令，这类指令通常用于存储数据。它涵盖了各种存储指令，例如 `sb` (存储字节), `sh` (存储半字), `sw` (存储字), `sd` (存储双字 - 仅限 64 位架构)，以及浮点存储指令 `fsw` 和 `fsd`。

**与 JavaScript 的关系：**

`v8/src/diagnostics/riscv/disasm-riscv.cc` 本身是用 C++ 编写的，不直接包含 JavaScript 代码。但是，它作为 V8 引擎的一部分，其功能与 JavaScript 的执行密切相关。

当 V8 引擎执行 JavaScript 代码时，它会将 JavaScript 代码编译成机器码，以便在 RISC-V 架构的处理器上运行。`disasm-riscv.cc` 中的代码就用于 **反汇编** 这些由 V8 生成的 RISC-V 机器码。这对于以下场景非常有用：

* **调试 V8 引擎:** 开发人员可以使用反汇编器来检查 V8 生成的机器码是否符合预期，从而帮助定位 V8 引擎本身的 bug。
* **性能分析:** 通过分析反汇编的代码，可以了解 JavaScript 代码在底层是如何执行的，从而进行性能优化。
* **理解 V8 的代码生成机制:** 研究反汇编结果可以帮助理解 V8 如何将高级的 JavaScript 代码转换为底层的机器指令。

**JavaScript 示例 (说明间接关系):**

```javascript
function add(a, b) {
  return a + b;
}

add(1, 2);
```

当 V8 执行这段 JavaScript 代码时，它会为 `add` 函数生成相应的 RISC-V 机器码。`v8/src/diagnostics/riscv/disasm-riscv.cc` 中的代码就可以被用来反汇编这些机器码，例如，你可能会看到类似于以下的 RISC-V 指令 (简化示例)：

```assembly
addi  x5, x10, x11  // 将寄存器 x10 和 x11 的值相加，结果存储到 x5
mv    x10, x5      // 将 x5 的值移动到 x10 (可能作为返回值)
ret               // 返回
```

**代码逻辑推理 (假设输入与输出):**

**假设输入:**  一个表示 RISC-V  `addi x1, x2, 10` 指令的 32 位二进制值 (假设为 `0x00A10093`)。

**代码逻辑:**  `Decoder::DecodeIType` 函数会被调用，它会提取指令中的操作码、寄存器号和立即数。具体来说：
- `instr->InstructionBits() & kITypeMask` 会匹配到 `RO_ADDI`。
- `instr->RdValue()` 会提取出目标寄存器 `x1` (代号 1)。
- `instr->Rs1Value()` 会提取出源寄存器 `x2` (代号 2)。
- `instr->Imm12Value()` 会提取出立即数 `10`。

**输出:**  `Format(instr, "addi      'rd, 'rs1, 'imm12");` 将会被调用，最终生成的格式化字符串可能是: `"addi      x1, x2, 10"`。

**用户常见的编程错误 (与反汇编相关):**

1. **误解反汇编结果:** 用户可能会错误地认为反汇编出的代码就是程序员编写的原始代码。实际上，编译器会进行各种优化，生成的机器码可能与原始代码有很大的差异。
   ```c++
   // 原始 C++ 代码
   int sum(int a, int b) {
       return a + b;
   }
   ```
   反汇编出的代码可能包含编译器为了优化性能而插入的指令，例如指令重排、使用不同的寄存器等，这可能与程序员最初的意图不完全一致。

2. **不理解指令语义:**  用户可能不熟悉 RISC-V 指令集的具体含义，导致对反汇编出的指令的功能理解错误。例如，不清楚 `lr.w` 和 `sc.w` 指令的原子性语义，可能会在并发编程中引入错误。

3. **假设反汇编结果的唯一性:**  对于相同的源代码，不同的编译器版本、编译选项或目标架构可能会生成不同的机器码。用户不能假设在一种情况下反汇编出的结果在所有情况下都相同。

**归纳一下它的功能 (第2部分):**

这部分代码主要负责解码和格式化 RISC-V 架构中 **原子操作** 和 **浮点运算** 相关的指令，以及 **I 型指令** 和 **S 型指令**。它通过分析指令的二进制位，识别出具体的指令类型和操作数，并将其转换为易于理解的汇编语言表示形式。这对于理解 V8 引擎生成的机器码、调试和性能分析至关重要。

Prompt: 
```
这是目录为v8/src/diagnostics/riscv/disasm-riscv.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/diagnostics/riscv/disasm-riscv.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
al. No
  // Memory address lock or other synchronizaiton behaviors.
  switch (instr->InstructionBits() & kRATypeMask) {
    case RO_LR_W:
      Format(instr, "lr.w'a    'rd, ('rs1)");
      break;
    case RO_SC_W:
      Format(instr, "sc.w'a    'rd, 'rs2, ('rs1)");
      break;
    case RO_AMOSWAP_W:
      Format(instr, "amoswap.w'a 'rd, 'rs2, ('rs1)");
      break;
    case RO_AMOADD_W:
      Format(instr, "amoadd.w'a 'rd, 'rs2, ('rs1)");
      break;
    case RO_AMOXOR_W:
      Format(instr, "amoxor.w'a 'rd, 'rs2, ('rs1)");
      break;
    case RO_AMOAND_W:
      Format(instr, "amoand.w'a 'rd, 'rs2, ('rs1)");
      break;
    case RO_AMOOR_W:
      Format(instr, "amoor.w'a 'rd, 'rs2, ('rs1)");
      break;
    case RO_AMOMIN_W:
      Format(instr, "amomin.w'a 'rd, 'rs2, ('rs1)");
      break;
    case RO_AMOMAX_W:
      Format(instr, "amomax.w'a 'rd, 'rs2, ('rs1)");
      break;
    case RO_AMOMINU_W:
      Format(instr, "amominu.w'a 'rd, 'rs2, ('rs1)");
      break;
    case RO_AMOMAXU_W:
      Format(instr, "amomaxu.w'a 'rd, 'rs2, ('rs1)");
      break;
#ifdef V8_TARGET_ARCH_64_BIT
    case RO_LR_D:
      Format(instr, "lr.d'a 'rd, ('rs1)");
      break;
    case RO_SC_D:
      Format(instr, "sc.d'a 'rd, 'rs2, ('rs1)");
      break;
    case RO_AMOSWAP_D:
      Format(instr, "amoswap.d'a 'rd, 'rs2, ('rs1)");
      break;
    case RO_AMOADD_D:
      Format(instr, "amoadd.d'a 'rd, 'rs2, ('rs1)");
      break;
    case RO_AMOXOR_D:
      Format(instr, "amoxor.d'a 'rd, 'rs2, ('rs1)");
      break;
    case RO_AMOAND_D:
      Format(instr, "amoand.d'a 'rd, 'rs2, ('rs1)");
      break;
    case RO_AMOOR_D:
      Format(instr, "amoor.d'a 'rd, 'rs2, ('rs1)");
      break;
    case RO_AMOMIN_D:
      Format(instr, "amomin.d'a 'rd, 'rs2, ('rs1)");
      break;
    case RO_AMOMAX_D:
      Format(instr, "amoswap.d'a 'rd, 'rs2, ('rs1)");
      break;
    case RO_AMOMINU_D:
      Format(instr, "amominu.d'a 'rd, 'rs2, ('rs1)");
      break;
    case RO_AMOMAXU_D:
      Format(instr, "amomaxu.d'a 'rd, 'rs2, ('rs1)");
      break;
#endif /*V8_TARGET_ARCH_64_BIT*/
    // TODO(riscv): End Add macro for RISCV A extension
    default: {
      UNSUPPORTED_RISCV();
    }
  }
}

void Decoder::DecodeRFPType(Instruction* instr) {
  // OP_FP instructions (F/D) uses func7 first. Some further uses fun3 and rs2()

  // kRATypeMask is only for func7
  switch (instr->InstructionBits() & kRFPTypeMask) {
    // TODO(riscv): Add macro for RISCV F extension
    case RO_FADD_S:
      Format(instr, "fadd.s    'fd, 'fs1, 'fs2");
      break;
    case RO_FSUB_S:
      Format(instr, "fsub.s    'fd, 'fs1, 'fs2");
      break;
    case RO_FMUL_S:
      Format(instr, "fmul.s    'fd, 'fs1, 'fs2");
      break;
    case RO_FDIV_S:
      Format(instr, "fdiv.s    'fd, 'fs1, 'fs2");
      break;
    case RO_FSQRT_S:
      Format(instr, "fsqrt.s   'fd, 'fs1");
      break;
    case RO_FSGNJ_S: {  // RO_FSGNJN_S  RO_FSGNJX_S
      switch (instr->Funct3Value()) {
        case 0b000:  // RO_FSGNJ_S
          if (instr->Rs1Value() == instr->Rs2Value())
            Format(instr, "fmv.s     'fd, 'fs1");
          else
            Format(instr, "fsgnj.s   'fd, 'fs1, 'fs2");
          break;
        case 0b001:  // RO_FSGNJN_S
          if (instr->Rs1Value() == instr->Rs2Value())
            Format(instr, "fneg.s    'fd, 'fs1");
          else
            Format(instr, "fsgnjn.s  'fd, 'fs1, 'fs2");
          break;
        case 0b010:  // RO_FSGNJX_S
          if (instr->Rs1Value() == instr->Rs2Value())
            Format(instr, "fabs.s    'fd, 'fs1");
          else
            Format(instr, "fsgnjx.s  'fd, 'fs1, 'fs2");
          break;
        default:
          UNSUPPORTED_RISCV();
      }
      break;
    }
    case RO_FMIN_S: {  // RO_FMAX_S
      switch (instr->Funct3Value()) {
        case 0b000:  // RO_FMIN_S
          Format(instr, "fmin.s    'fd, 'fs1, 'fs2");
          break;
        case 0b001:  // RO_FMAX_S
          Format(instr, "fmax.s    'fd, 'fs1, 'fs2");
          break;
        default:
          UNSUPPORTED_RISCV();
      }
      break;
    }
    case RO_FCVT_W_S: {  // RO_FCVT_WU_S , 64F RO_FCVT_L_S RO_FCVT_LU_S
      switch (instr->Rs2Value()) {
        case 0b00000:  // RO_FCVT_W_S
          Format(instr, "fcvt.w.s  ['frm] 'rd, 'fs1");
          break;
        case 0b00001:  // RO_FCVT_WU_S
          Format(instr, "fcvt.wu.s ['frm] 'rd, 'fs1");
          break;
#ifdef V8_TARGET_ARCH_64_BIT
        case 0b00010:  // RO_FCVT_L_S
          Format(instr, "fcvt.l.s  ['frm] 'rd, 'fs1");
          break;
        case 0b00011:  // RO_FCVT_LU_S
          Format(instr, "fcvt.lu.s ['frm] 'rd, 'fs1");
          break;
#endif /* V8_TARGET_ARCH_64_BIT */
        default:
          UNSUPPORTED_RISCV();
      }
      break;
    }
    case RO_FMV: {  // RO_FCLASS_S
      if (instr->Rs2Value() != 0b00000) {
        UNSUPPORTED_RISCV();
      }
      switch (instr->Funct3Value()) {
        case 0b000:  // RO_FMV_X_W
          Format(instr, "fmv.x.w   'rd, 'fs1");
          break;
        case 0b001:  // RO_FCLASS_S
          Format(instr, "fclass.s  'rd, 'fs1");
          break;
        default:
          UNSUPPORTED_RISCV();
      }
      break;
    }
    case RO_FLE_S: {  // RO_FEQ_S RO_FLT_S RO_FLE_S
      switch (instr->Funct3Value()) {
        case 0b010:  // RO_FEQ_S
          Format(instr, "feq.s     'rd, 'fs1, 'fs2");
          break;
        case 0b001:  // RO_FLT_S
          Format(instr, "flt.s     'rd, 'fs1, 'fs2");
          break;
        case 0b000:  // RO_FLE_S
          Format(instr, "fle.s     'rd, 'fs1, 'fs2");
          break;
        default:
          UNSUPPORTED_RISCV();
      }
      break;
    }
    case RO_FCVT_S_W: {  // RO_FCVT_S_WU , 64F RO_FCVT_S_L RO_FCVT_S_LU
      switch (instr->Rs2Value()) {
        case 0b00000:  // RO_FCVT_S_W
          Format(instr, "fcvt.s.w  'fd, 'rs1");
          break;
        case 0b00001:  // RO_FCVT_S_WU
          Format(instr, "fcvt.s.wu 'fd, 'rs1");
          break;
#ifdef V8_TARGET_ARCH_64_BIT
        case 0b00010:  // RO_FCVT_S_L
          Format(instr, "fcvt.s.l  'fd, 'rs1");
          break;
        case 0b00011:  // RO_FCVT_S_LU
          Format(instr, "fcvt.s.lu 'fd, 'rs1");
          break;
#endif /* V8_TARGET_ARCH_64_BIT */
        default: {
          UNSUPPORTED_RISCV();
        }
      }
      break;
    }
    case RO_FMV_W_X: {
      if (instr->Funct3Value() == 0b000) {
        Format(instr, "fmv.w.x   'fd, 'rs1");
      } else {
        UNSUPPORTED_RISCV();
      }
      break;
    }
    // TODO(riscv): Add macro for RISCV D extension
    case RO_FADD_D:
      Format(instr, "fadd.d    'fd, 'fs1, 'fs2");
      break;
    case RO_FSUB_D:
      Format(instr, "fsub.d    'fd, 'fs1, 'fs2");
      break;
    case RO_FMUL_D:
      Format(instr, "fmul.d    'fd, 'fs1, 'fs2");
      break;
    case RO_FDIV_D:
      Format(instr, "fdiv.d    'fd, 'fs1, 'fs2");
      break;
    case RO_FSQRT_D: {
      if (instr->Rs2Value() == 0b00000) {
        Format(instr, "fsqrt.d   'fd, 'fs1");
      } else {
        UNSUPPORTED_RISCV();
      }
      break;
    }
    case RO_FSGNJ_D: {  // RO_FSGNJN_D RO_FSGNJX_D
      switch (instr->Funct3Value()) {
        case 0b000:  // RO_FSGNJ_D
          if (instr->Rs1Value() == instr->Rs2Value())
            Format(instr, "fmv.d     'fd, 'fs1");
          else
            Format(instr, "fsgnj.d   'fd, 'fs1, 'fs2");
          break;
        case 0b001:  // RO_FSGNJN_D
          if (instr->Rs1Value() == instr->Rs2Value())
            Format(instr, "fneg.d    'fd, 'fs1");
          else
            Format(instr, "fsgnjn.d  'fd, 'fs1, 'fs2");
          break;
        case 0b010:  // RO_FSGNJX_D
          if (instr->Rs1Value() == instr->Rs2Value())
            Format(instr, "fabs.d    'fd, 'fs1");
          else
            Format(instr, "fsgnjx.d  'fd, 'fs1, 'fs2");
          break;
        default:
          UNSUPPORTED_RISCV();
      }
      break;
    }
    case RO_FMIN_D: {  // RO_FMAX_D
      switch (instr->Funct3Value()) {
        case 0b000:  // RO_FMIN_D
          Format(instr, "fmin.d    'fd, 'fs1, 'fs2");
          break;
        case 0b001:  // RO_FMAX_D
          Format(instr, "fmax.d    'fd, 'fs1, 'fs2");
          break;
        default:
          UNSUPPORTED_RISCV();
      }
      break;
    }
    case (RO_FCVT_S_D & kRFPTypeMask): {
      if (instr->Rs2Value() == 0b00001) {
        Format(instr, "fcvt.s.d  ['frm] 'fd, 'fs1");
      } else {
        UNSUPPORTED_RISCV();
      }
      break;
    }
    case RO_FCVT_D_S: {
      if (instr->Rs2Value() == 0b00000) {
        Format(instr, "fcvt.d.s  'fd, 'fs1");
      } else {
        UNSUPPORTED_RISCV();
      }
      break;
    }
    case RO_FLE_D: {  // RO_FEQ_D RO_FLT_D RO_FLE_D
      switch (instr->Funct3Value()) {
        case 0b010:  // RO_FEQ_S
          Format(instr, "feq.d     'rd, 'fs1, 'fs2");
          break;
        case 0b001:  // RO_FLT_D
          Format(instr, "flt.d     'rd, 'fs1, 'fs2");
          break;
        case 0b000:  // RO_FLE_D
          Format(instr, "fle.d     'rd, 'fs1, 'fs2");
          break;
        default:
          UNSUPPORTED_RISCV();
      }
      break;
    }
    case (RO_FCLASS_D & kRFPTypeMask): {  // RO_FCLASS_D , 64D RO_FMV_X_D
      if (instr->Rs2Value() != 0b00000) {
        UNSUPPORTED_RISCV();
      }
      switch (instr->Funct3Value()) {
        case 0b001:  // RO_FCLASS_D
          Format(instr, "fclass.d  'rd, 'fs1");
          break;
#ifdef V8_TARGET_ARCH_64_BIT
        case 0b000:  // RO_FMV_X_D
          Format(instr, "fmv.x.d   'rd, 'fs1");
          break;
#endif /* V8_TARGET_ARCH_64_BIT */
        default:
          UNSUPPORTED_RISCV();
      }
      break;
    }
    case RO_FCVT_W_D: {  // RO_FCVT_WU_D , 64F RO_FCVT_L_D RO_FCVT_LU_D
      switch (instr->Rs2Value()) {
        case 0b00000:  // RO_FCVT_W_D
          Format(instr, "fcvt.w.d  ['frm] 'rd, 'fs1");
          break;
        case 0b00001:  // RO_FCVT_WU_D
          Format(instr, "fcvt.wu.d ['frm] 'rd, 'fs1");
          break;
#ifdef V8_TARGET_ARCH_64_BIT
        case 0b00010:  // RO_FCVT_L_D
          Format(instr, "fcvt.l.d  ['frm] 'rd, 'fs1");
          break;
        case 0b00011:  // RO_FCVT_LU_D
          Format(instr, "fcvt.lu.d ['frm] 'rd, 'fs1");
          break;
#endif /* V8_TARGET_ARCH_64_BIT */
        default:
          UNSUPPORTED_RISCV();
      }
      break;
    }
    case RO_FCVT_D_W: {  // RO_FCVT_D_WU , 64F RO_FCVT_D_L RO_FCVT_D_LU
      switch (instr->Rs2Value()) {
        case 0b00000:  // RO_FCVT_D_W
          Format(instr, "fcvt.d.w  'fd, 'rs1");
          break;
        case 0b00001:  // RO_FCVT_D_WU
          Format(instr, "fcvt.d.wu 'fd, 'rs1");
          break;
#ifdef V8_TARGET_ARCH_64_BIT
        case 0b00010:  // RO_FCVT_D_L
          Format(instr, "fcvt.d.l  'fd, 'rs1");
          break;
        case 0b00011:  // RO_FCVT_D_LU
          Format(instr, "fcvt.d.lu 'fd, 'rs1");
          break;
#endif /* V8_TARGET_ARCH_64_BIT */
        default:
          UNSUPPORTED_RISCV();
      }
      break;
    }
#ifdef V8_TARGET_ARCH_64_BIT
    case RO_FMV_D_X: {
      if (instr->Funct3Value() == 0b000 && instr->Rs2Value() == 0b00000) {
        Format(instr, "fmv.d.x   'fd, 'rs1");
      } else {
        UNSUPPORTED_RISCV();
      }
      break;
    }
#endif /* V8_TARGET_ARCH_64_BIT */
    default: {
      UNSUPPORTED_RISCV();
    }
  }
}

void Decoder::DecodeR4Type(Instruction* instr) {
  switch (instr->InstructionBits() & kR4TypeMask) {
    // TODO(riscv): use F Extension macro block
    case RO_FMADD_S:
      Format(instr, "fmadd.s   'fd, 'fs1, 'fs2, 'fs3");
      break;
    case RO_FMSUB_S:
      Format(instr, "fmsub.s   'fd, 'fs1, 'fs2, 'fs3");
      break;
    case RO_FNMSUB_S:
      Format(instr, "fnmsub.s   'fd, 'fs1, 'fs2, 'fs3");
      break;
    case RO_FNMADD_S:
      Format(instr, "fnmadd.s   'fd, 'fs1, 'fs2, 'fs3");
      break;
    // TODO(riscv): use F Extension macro block
    case RO_FMADD_D:
      Format(instr, "fmadd.d   'fd, 'fs1, 'fs2, 'fs3");
      break;
    case RO_FMSUB_D:
      Format(instr, "fmsub.d   'fd, 'fs1, 'fs2, 'fs3");
      break;
    case RO_FNMSUB_D:
      Format(instr, "fnmsub.d  'fd, 'fs1, 'fs2, 'fs3");
      break;
    case RO_FNMADD_D:
      Format(instr, "fnmadd.d  'fd, 'fs1, 'fs2, 'fs3");
      break;
    default:
      UNSUPPORTED_RISCV();
  }
}

void Decoder::DecodeIType(Instruction* instr) {
  switch (instr->InstructionBits() & kITypeMask) {
    case RO_JALR:
      if (instr->RdValue() == zero_reg.code() &&
          instr->Rs1Value() == ra.code() && instr->Imm12Value() == 0)
        Format(instr, "ret");
      else if (instr->RdValue() == zero_reg.code() && instr->Imm12Value() == 0)
        Format(instr, "jr        'rs1");
      else if (instr->RdValue() == ra.code() && instr->Imm12Value() == 0)
        Format(instr, "jalr      'rs1");
      else
        Format(instr, "jalr      'rd, 'imm12('rs1)");
      break;
    case RO_LB:
      Format(instr, "lb        'rd, 'imm12('rs1)");
      break;
    case RO_LH:
      Format(instr, "lh        'rd, 'imm12('rs1)");
      break;
    case RO_LW:
      Format(instr, "lw        'rd, 'imm12('rs1)");
      break;
    case RO_LBU:
      Format(instr, "lbu       'rd, 'imm12('rs1)");
      break;
    case RO_LHU:
      Format(instr, "lhu       'rd, 'imm12('rs1)");
      break;
#ifdef V8_TARGET_ARCH_64_BIT
    case RO_LWU:
      Format(instr, "lwu       'rd, 'imm12('rs1)");
      break;
    case RO_LD:
      Format(instr, "ld        'rd, 'imm12('rs1)");
      break;
#endif /*V8_TARGET_ARCH_64_BIT*/
    case RO_ADDI:
      if (instr->Imm12Value() == 0) {
        if (instr->RdValue() == zero_reg.code() &&
            instr->Rs1Value() == zero_reg.code())
          Format(instr, "nop");
        else
          Format(instr, "mv        'rd, 'rs1");
      } else if (instr->Rs1Value() == zero_reg.code()) {
        Format(instr, "li        'rd, 'imm12");
      } else {
        Format(instr, "addi      'rd, 'rs1, 'imm12");
      }
      break;
    case RO_SLTI:
      Format(instr, "slti      'rd, 'rs1, 'imm12");
      break;
    case RO_SLTIU:
      if (instr->Imm12Value() == 1)
        Format(instr, "seqz      'rd, 'rs1");
      else
        Format(instr, "sltiu     'rd, 'rs1, 'imm12");
      break;
    case RO_XORI:
      if (instr->Imm12Value() == -1)
        Format(instr, "not       'rd, 'rs1");
      else
        Format(instr, "xori      'rd, 'rs1, 'imm12x");
      break;
    case RO_ORI:
      Format(instr, "ori       'rd, 'rs1, 'imm12x");
      break;
    case RO_ANDI:
      Format(instr, "andi      'rd, 'rs1, 'imm12x");
      break;
    case OP_SHL:
      switch (instr->Funct6FieldRaw() | OP_SHL) {
        case RO_SLLI:
          Format(instr, "slli      'rd, 'rs1, 's64");
          break;
        case RO_BCLRI:
          Format(instr, "bclri     'rd, 'rs1, 's64");
          break;
        case RO_BINVI:
          Format(instr, "binvi     'rd, 'rs1, 's64");
          break;
        case RO_BSETI:
          Format(instr, "bseti     'rd, 'rs1, 's64");
          break;
        case OP_COUNT:
          switch (instr->Shamt()) {
            case 0:
              Format(instr, "clz       'rd, 'rs1");
              break;
            case 1:
              Format(instr, "ctz       'rd, 'rs1");
              break;
            case 2:
              Format(instr, "cpop      'rd, 'rs1");
              break;
            case 4:
              Format(instr, "sext.b    'rd, 'rs1");
              break;
            case 5:
              Format(instr, "sext.h    'rd, 'rs1");
              break;
            default:
              UNSUPPORTED_RISCV();
          }
          break;
        default:
          UNSUPPORTED_RISCV();
      }
      break;
    case OP_SHR: {  //  RO_SRAI
      switch (instr->Funct6FieldRaw() | OP_SHR) {
        case RO_SRLI:
          Format(instr, "srli      'rd, 'rs1, 's64");
          break;
        case RO_SRAI:
          Format(instr, "srai      'rd, 'rs1, 's64");
          break;
        case RO_BEXTI:
          Format(instr, "bexti     'rd, 'rs1, 's64");
          break;
        case RO_ORCB&(kFunct6Mask | OP_SHR):
          Format(instr, "orc.b     'rd, 'rs1");
          break;
        case RO_RORI:
#ifdef V8_TARGET_ARCH_64_BIT
          Format(instr, "rori      'rd, 'rs1, 's64");
          break;
#elif defined(V8_TARGET_ARCH_RISCV32)
          Format(instr, "rori      'rd, 'rs1, 's32");
          break;
#endif
        case RO_REV8: {
          if (instr->Imm12Value() == RO_REV8_IMM12) {
            Format(instr, "rev8      'rd, 'rs1");
            break;
          }
          UNSUPPORTED_RISCV();
        }
        default:
          UNSUPPORTED_RISCV();
      }
      break;
    }
#ifdef V8_TARGET_ARCH_64_BIT
    case RO_ADDIW:
      if (instr->Imm12Value() == 0)
        Format(instr, "sext.w    'rd, 'rs1");
      else
        Format(instr, "addiw     'rd, 'rs1, 'imm12");
      break;
    case OP_SHLW:
      switch (instr->Funct7FieldRaw() | OP_SHLW) {
        case RO_SLLIW:
          Format(instr, "slliw     'rd, 'rs1, 's32");
          break;
        case RO_SLLIUW:
          Format(instr, "slli.uw   'rd, 'rs1, 's32");
          break;
        case OP_COUNTW: {
          switch (instr->Shamt()) {
            case 0:
              Format(instr, "clzw      'rd, 'rs1");
              break;
            case 1:
              Format(instr, "ctzw      'rd, 'rs1");
              break;
            case 2:
              Format(instr, "cpopw     'rd, 'rs1");
              break;
            default:
              UNSUPPORTED_RISCV();
          }
          break;
        }
        default:
          UNSUPPORTED_RISCV();
      }
      break;
    case OP_SHRW: {  //  RO_SRAI
      switch (instr->Funct7FieldRaw() | OP_SHRW) {
        case RO_SRLIW:
          Format(instr, "srliw     'rd, 'rs1, 's32");
          break;
        case RO_SRAIW:
          Format(instr, "sraiw     'rd, 'rs1, 's32");
          break;
        case RO_RORIW:
          Format(instr, "roriw     'rd, 'rs1, 's32");
          break;
        default:
          UNSUPPORTED_RISCV();
      }
      break;
    }
#endif /*V8_TARGET_ARCH_64_BIT*/
    case RO_FENCE:
      if (instr->MemoryOrder(true) == PSIORW &&
          instr->MemoryOrder(false) == PSIORW)
        Format(instr, "fence");
      else
        Format(instr, "fence 'pre, 'suc");
      break;
    case RO_ECALL: {                   // RO_EBREAK
      if (instr->Imm12Value() == 0) {  // ECALL
        Format(instr, "ecall");
      } else if (instr->Imm12Value() == 1) {  // EBREAK
        Format(instr, "ebreak");
      } else {
        UNSUPPORTED_RISCV();
      }
      break;
    }
    // TODO(riscv): use Zifencei Standard Extension macro block
    case RO_FENCE_I:
      Format(instr, "fence.i");
      break;
    // TODO(riscv): use Zicsr Standard Extension macro block
    // FIXME(RISC-V): Add special formatting for CSR registers
    case RO_CSRRW:
      if (instr->CsrValue() == csr_fcsr) {
        if (instr->RdValue() == zero_reg.code())
          Format(instr, "fscsr     'rs1");
        else
          Format(instr, "fscsr     'rd, 'rs1");
      } else if (instr->CsrValue() == csr_frm) {
        if (instr->RdValue() == zero_reg.code())
          Format(instr, "fsrm      'rs1");
        else
          Format(instr, "fsrm      'rd, 'rs1");
      } else if (instr->CsrValue() == csr_fflags) {
        if (instr->RdValue() == zero_reg.code())
          Format(instr, "fsflags   'rs1");
        else
          Format(instr, "fsflags   'rd, 'rs1");
      } else if (instr->RdValue() == zero_reg.code()) {
        Format(instr, "csrw      'csr, 'rs1");
      } else {
        Format(instr, "csrrw     'rd, 'csr, 'rs1");
      }
      break;
    case RO_CSRRS:
      if (instr->Rs1Value() == zero_reg.code()) {
        switch (instr->CsrValue()) {
          case csr_instret:
            Format(instr, "rdinstret 'rd");
            break;
          case csr_instreth:
            Format(instr, "rdinstreth 'rd");
            break;
          case csr_time:
            Format(instr, "rdtime    'rd");
            break;
          case csr_timeh:
            Format(instr, "rdtimeh   'rd");
            break;
          case csr_cycle:
            Format(instr, "rdcycle   'rd");
            break;
          case csr_cycleh:
            Format(instr, "rdcycleh  'rd");
            break;
          case csr_fflags:
            Format(instr, "frflags   'rd");
            break;
          case csr_frm:
            Format(instr, "frrm      'rd");
            break;
          case csr_fcsr:
            Format(instr, "frcsr     'rd");
            break;
          default:
            UNREACHABLE();
        }
      } else if (instr->Rs1Value() == zero_reg.code()) {
        Format(instr, "csrr      'rd, 'csr");
      } else if (instr->RdValue() == zero_reg.code()) {
        Format(instr, "csrs      'csr, 'rs1");
      } else {
        Format(instr, "csrrs     'rd, 'csr, 'rs1");
      }
      break;
    case RO_CSRRC:
      if (instr->RdValue() == zero_reg.code())
        Format(instr, "csrc      'csr, 'rs1");
      else
        Format(instr, "csrrc     'rd, 'csr, 'rs1");
      break;
    case RO_CSRRWI:
      if (instr->RdValue() == zero_reg.code())
        Format(instr, "csrwi     'csr, 'uimm");
      else
        Format(instr, "csrrwi    'rd, 'csr, 'uimm");
      break;
    case RO_CSRRSI:
      if (instr->RdValue() == zero_reg.code())
        Format(instr, "csrsi     'csr, 'uimm");
      else
        Format(instr, "csrrsi    'rd, 'csr, 'uimm");
      break;
    case RO_CSRRCI:
      if (instr->RdValue() == zero_reg.code())
        Format(instr, "csrci     'csr, 'uimm");
      else
        Format(instr, "csrrci    'rd, 'csr, 'uimm");
      break;
    // TODO(riscv): use F Extension macro block
    case RO_FLW:
      Format(instr, "flw       'fd, 'imm12('rs1)");
      break;
    // TODO(riscv): use D Extension macro block
    case RO_FLD:
      Format(instr, "fld       'fd, 'imm12('rs1)");
      break;
    default:
#ifdef CAN_USE_RVV_INSTRUCTIONS
      if (instr->vl_vs_width() != -1) {
        DecodeRvvVL(instr);
      } else {
        UNSUPPORTED_RISCV();
      }
      break;
#else
      UNSUPPORTED_RISCV();
#endif
  }
}

void Decoder::DecodeSType(Instruction* instr) {
  switch (instr->InstructionBits() & kSTypeMask) {
    case RO_SB:
      Format(instr, "sb        'rs2, 'offS('rs1)");
      break;
    case RO_SH:
      Format(instr, "sh        'rs2, 'offS('rs1)");
      break;
    case RO_SW:
      Format(instr, "sw        'rs2, 'offS('rs1)");
      break;
#ifdef V8_TARGET_ARCH_64_BIT
    case RO_SD:
      Format(instr, "sd        'rs2, 'offS('rs1)");
      break;
#endif /*V8_TARGET_ARCH_64_BIT*/
    // TODO(riscv): use F Extension macro block
    case RO_FSW:
      Format(instr, "fsw       'fs2, 'offS('rs1)");
      break;
    // TODO(riscv): use D Extension macro block
    case RO_FSD:
      Format(instr, "fsd       'fs2, 'offS('rs1)");
      break;
    default:
#ifdef CAN_USE_RVV_INSTRUCTIONS
      if (instr->vl_vs_width() != -1) {
        DecodeRvvVS(instr);
      } else {
        UNSUPPORTED_RISCV();
      }
      break;
#else
      UNSUPPORTED_RISCV();
#endif
  }
}

void Decoder::DecodeBType(Instruction* instr) {
  switch (instr->InstructionBits() & kBTypeMask) {
    case RO_BEQ:
      Format(instr, "beq       'rs1, 'rs2, 'offB");
      break;
    case RO_BNE:
      Format(instr, "bne       'rs1, 'rs2, 'offB");
      break;
    case RO_BLT:
      Format(instr, "blt       'rs1, 'rs2, 'offB");
      break;
    case RO_BGE:
      Format(instr, "bge       'rs1, 'rs2, 'offB");
      break;
    case RO_BLTU:
      Format(instr, "bltu      'rs1, 'rs2, 'offB");
      break;
    case RO_BGEU:
      Format(instr, "bgeu      'rs1, 'rs2, 'offB");
      break;
    default:
      UNSUPPORTED_RISCV();
  }
}
void Decoder::DecodeUType(Instruction* instr) {
  // U Type doesn't have additional mask
  switch (instr->BaseOpcodeFieldRaw()) {
    case LUI:
      Format(instr, "lui       'rd, 'imm20U");
      break;
    case AUIPC:
      Format(instr, "auipc     'rd, 'imm20U");
      break;
    default:
      UNSUPPORTED_RISCV();
  }
}
// namespace internal
void Decoder::DecodeJType(Instruction* instr) {
  // J Type doesn't have additional mask
  switch (instr->BaseOpcodeValue()) {
    case JAL:
      if (instr->RdValue() == zero_reg.code())
        Format(instr, "j         'imm20J");
      else if (instr->RdValue() == ra.code())
        Format(instr, "jal       'imm20J");
      else
        Format(instr, "jal       'rd, 'imm20J");
      break;
    default:
      UNSUPPORTED_RISCV();
  }
}

void Decoder::DecodeCRType(Instruction* instr) {
  switch (instr->RvcFunct4Value()) {
    case 0b1000:
      if (instr->RvcRs1Value() != 0 && instr->RvcRs2Value() == 0) {
        Format(instr, "jr        'Crs1");
        break;
      } else if (instr->RvcRdValue() != 0 && instr->RvcRs2Value() != 0) {
        Format(instr, "mv        'Crd, 'Crs2");
        break;
      } else {
        UNSUPPORTED_RISCV();
      }
    case 0b1001:
      if (instr->RvcRs1Value() == 0 && instr->RvcRs2Value() == 0) {
        Format(instr, "ebreak");
        break;
      } else if (instr->RvcRdValue() != 0 && instr->RvcRs2Value() == 0) {
        Format(instr, "jalr      'Crs1");
        break;
      } else if (instr->RvcRdValue() != 0 && instr->RvcRs2Value() != 0) {
        Format(instr, "add       'Crd, 'Crd, 'Crs2");
        break;
      } else {
        UNSUPPORTED_RISCV();
      }
    default:
      UNSUPPORTED_RISCV();
  }
}

void Decoder::DecodeCAType(Instruction* instr) {
  switch (instr->InstructionBits() & kCATypeMask) {
    case RO_C_SUB:
      Format(instr, "sub       'Crs1s, 'Crs1s, 'Crs2s");
      break;
    case RO_C_XOR:
      Format(instr, "xor       'Crs1s, 'Crs1s, 'Crs2s");
      break;
    case RO_C_OR:
      Format(instr, "or       'Crs1s, 'Crs1s, 'Crs2s");
      break;
    case RO_C_AND:
      Format(instr, "and       'Crs1s, 'Crs1s, 'Crs2s");
      break;
#ifdef V8_TARGET_ARCH_64_BIT
    case RO_C_SUBW:
      Format(instr, "subw       'Crs1s, 'Crs1s, 'Crs2s");
      break;
    case RO_C_ADDW:
      Format(instr, "addw       'Crs1s, 'Crs1s, 'Crs2s");
      break;
#endif
    default:
      UNSUPPORTED_RISCV();
  }
}

void Decoder::DecodeCIType(Instruction* instr) {
  switch (instr->RvcOpcode()) {
    case RO_C_NOP_ADDI:
      if (instr->RvcRdValue() == 0)
        Format(instr, "nop");
      else
        Format(instr, "addi      'Crd, 'Crd, 'Cimm6");
      break;
#ifdef V8_TARGET_ARCH_64_BIT
    case RO_C_ADDIW:
      Format(instr, "addiw     'Crd, 'Crd, 'Cimm6");
      break;
#endif
    case RO_C_LI:
      Format(instr, "li        'Crd, 'Cimm6");
      break;
    case RO_C_LUI_ADD:
      if (instr->RvcRdValue() == 2) {
        Format(instr, "addi      sp, sp, 'Cimm6Addi16sp");
        break;
      } else if (instr->RvcRdValue() != 0 && instr->RvcRdValue() != 2) {
        Format(instr, "lui       'Crd, 'Cimm6U");
        break;
      } else {
        UNSUPPORTED_RISCV();
      }
    case RO_C_SLLI:
      Format(instr, "slli      'Crd, 'Crd, 'Cshamt");
      break;
    case RO_C_FLDSP:
      Format(instr, "fld       'Cfd, 'Cimm6Ldsp(sp)");
      break;
    case RO_C_LWSP:
      Format(instr, "lw        'Crd, 'Cimm6Lwsp(sp)");
      break;
#ifdef V8_TARGET_ARCH_64_BIT
    case RO_C_LDSP:
      Format(instr, "ld        'Crd, 'Cimm6Ldsp(sp)");
      break;
#elif defined(V8_TARGET_ARCH_32_BIT)
    case RO_C_FLWSP:
      Format(instr, "flw       'Cfd, 'Cimm6Ldsp(sp)");
      break;
#endif
    default:
      UNSUPPORTED_RISCV();
  }
}

void Decoder::DecodeCIWType(Instruction* instr) {
  switch (instr->RvcOpcode()) {
    case RO_C_ADDI4SPN:
      Format(instr, "addi       'Crs2s, sp, 'Cimm8Addi4spn");
      break;
    default:
      UNSUPPORTED_RISCV();
  }
}

void Decoder::DecodeCSSType(Instruction* instr) {
  switch (instr->RvcOpcode()) {
    case RO_C_SWSP:
      Format(instr, "sw        'Crs2, 'Cimm6Swsp(sp)");
      break;
#ifdef V8_TARGET_ARCH_64_BIT
    case RO_C_SDSP:
      Format(instr, "sd        'Crs2, 'Cimm6Sdsp(sp)");
      break;
#elif defined(V8_TARGET_ARCH_32_BIT)
    case RO_C_FSWSP:
      Format(instr, "fsw       'Cfs2, 'Cimm6Sdsp(sp)");
      break;
#endif
    case RO_C_FSDSP:
      Format(instr, "fsd       'Cfs2, 'Cimm6Sdsp(sp)");
      break;
    default:
      UNSUPPORTED_RISCV();
  }
}

void Decoder::DecodeCLType(Instruction* instr) {
  switch (instr->RvcOpcode()) {
    case RO_C_FLD:
      Format(instr, "fld       'Cfs2s, 'Cimm5D('Crs1s)");
      break;
    case RO_C_LW:
      Format(instr, "lw       'Crs2s, 'Cimm5W('Crs1s)");
      break;
#ifdef V8_TARGET_ARCH_64_BIT
    case RO_C_LD:
      Format(instr, "ld       'Crs2s, 'Cimm5D('Crs1s)");
      break;
#elif defined(V8_TARGET_ARCH_32_BIT)
    case RO_C_FLW:
      Format(instr, "fld       'Cfs2s, 'Cimm5D('Crs1s)");
      break;
#endif

    default:
      UNSUPPORTED_RISCV();
  }
}

void Decoder::DecodeCSType(Instruction* instr) {
  switch (instr->RvcOpcode()) {
    case RO_C_FSD:
      Format(instr, "fsd       'Cfs2s, 'Cimm5D('Crs1s)");
      break;
    case RO_C_SW:
      Format(instr, "sw       'Crs2s, 'Cimm5W('Crs1s)");
      break;
#ifdef V8_TARGET_ARCH_64_BIT
    case RO_C_SD:
      Format(instr, "sd       'Crs2s, 'Cimm5D('Crs1s)");
      break;
#elif defined(V8_TARGET_ARCH_32_BIT)
    case RO_C_FSW:
      Format(instr, "fsw       'Cfs2s, 'Cimm5D('Crs1s)");
      break;
#endif
    default:
      UNSUPPORTED_RISCV();
  }
}

void Decoder::DecodeCJType(Instruction* instr) {
  switch (instr->RvcOpcode()) {
    case RO_C_J:
      Format(instr, "j       'Cimm11CJ");
      break;
    default:
      UNSUPPORTED_RISCV();
  }
}

void Decoder::DecodeCBType(Instruction* instr) {
  switch (instr->RvcOpcode()) {
    case RO_C_BNEZ:
      Format(instr, "bnez       'Crs1s, x0, 'Cimm8B");
      break;
    case RO_C_BEQZ:
      Format(instr, "beqz       'Crs1s, x0, 'Cimm8B");
      break;
    case RO_C_MISC_ALU:
      if (instr->RvcFunct2BValue() == 0b00) {
        Format(instr, "srli       'Crs1s, 'Crs1s, 'Cshamt");
        break;
      } else if (instr->RvcFunct2BValue() == 0b01) {
        Format(instr, "srai       'Crs1s, 'Crs1s, 'Cshamt");
        break;
      } else if (instr->RvcFunct2BValue() == 0b10) {
        Format(instr, "andi       'Crs1s, 'Crs1s, 'Cimm6");
        break;
      } else {
        UNSUPPORTED_RISCV();
      }
    default:
      UNSUPPORTED_RISCV();
  }
}

void Decoder::DecodeRvvIVV(Instruction* instr) {
  DCHECK_EQ(instr->InstructionBits() & (kBaseOpcodeMask | kFunct3Mask), OP_IVV);
  switch (instr->InstructionBits() & kVTypeMask) {
    case RO_V_VADD_VV:
      Format(instr, "vadd.vv   'vd, 'vs2, 'vs1'vm");
      break;
    case RO_V_VSADD_VV:
      Format(instr, "vsadd.vv  'vd, 'vs2, 'vs1'vm");
      break;
    case RO_V_VSADDU_VV:
      Format(instr, "vsaddu.vv 'vd, 'vs2, 'vs1'vm");
      break;
    case RO_V_VSUB_VV:
      Format(instr, "vsub.vv   'vd, 'vs2, 'vs1'vm");
      break;
    case RO_V_VSSUB_VV:
      Format(instr, "vssub.vv  'vd, 'vs2, 'vs1'vm");
      break;
    case RO_V_VSSUBU_VV:
      Format(instr, "vssubu.vv  'vd, 'vs2, 'vs1'vm");
      break;
    case RO_V_VMIN_VV:
      Format(instr, "vmin.vv   'vd, 'vs2, 'vs1'vm");
      break;
    case RO_V_VMINU_VV:
      Format(instr, "vminu.vv  'vd, 'vs2, 'vs1'vm");
      break;
    case RO_V_VMAX_VV:
      Format(instr, "vmax.vv   'vd, 'vs2, 'vs1'vm");
      break;
    case RO_V_VMAXU_VV:
      Format(instr, "vmaxu.vv  'vd, 'vs2, 'vs1'vm");
      break;
    case RO_V_VAND_VV:
      Format(instr, "vand.vv   'vd, 'vs2, 'vs1'vm");
      break;
    case RO_V_VOR_VV:
      Format(instr, "vor.vv    'vd, 'vs2, 'vs1'vm");
      break;
    case RO_V_VXOR_VV:
      Format(instr, "vxor.vv   'vd, 'vs2, 'vs1'vm");
      break;
    case RO_V_VRGATHER_VV:
      Format(instr, "vrgather.vv 'vd, 'vs2, 'vs1'vm");
      break;
    case RO_V_VMSEQ_VV:
      Format(instr, "vmseq.vv  'vd, 'vs2, 'vs1'vm");
      break;
    case RO_V_VMSNE_VV:
      Format(instr, "vmsne.vv  'vd, 'vs2, 'vs1'vm");
      break;
    case RO_V_VMSLT_VV:
      Format(instr, "vmslt.vv  'vd, 'vs2, 'vs1'vm");
      break;
    case RO_V_VMSLTU_VV:
      Format(instr, "vmsltu.vv 'vd, 'vs2, 'vs1'vm");
      break;
    case RO_V_VMSLE_VV:
      Format(instr, "vmsle.vv  'vd, 'vs2, 'vs1'vm");
      break;
    case RO_V_VMSLEU_VV:
      Format(instr, "vmsleu.vv 'vd, 'vs2, 'vs1'vm");
      break;
    case RO_V_VMV_VV:
      if (instr->RvvVM()) {
        Format(instr, "vmv.vv    'vd, 'vs1");
      } else {
        Format(instr, "vmerge.vvm 'vd, 'vs2, 'vs1, v0");
      }
      break;
    case RO_V_VADC_VV:
      if (!instr->RvvVM()) {
        Format(instr, "vadc.vvm  'vd, 'vs2, '
"""


```