Response:
Let's break down the thought process for analyzing this code snippet.

1. **Understand the Goal:** The core request is to analyze a C++ file (`simulator-s390.cc`) from the V8 JavaScript engine. The analysis should cover functionality, potential Torque relationship, JavaScript relevance, code logic examples, common errors, and a summary, all within the context of being the 7th part of a larger analysis.

2. **Initial Scan and Keyword Spotting:**  Quickly read through the code looking for patterns and familiar concepts. Keywords like `EVALUATE`, `DCHECK_OPCODE`, `DECODE_`, `get_register`, `set_register`, `Read`, `Write`, `SetS390ConditionCode`, `UNIMPLEMENTED`, etc., stand out. These strongly suggest the code is simulating the execution of S390 assembly instructions.

3. **Identify the Core Functionality:** The presence of `EVALUATE(INSTRUCTION_NAME)` blocks clearly indicates that this code is responsible for implementing the behavior of individual S390 instructions. Each `EVALUATE` block corresponds to a specific S390 assembly instruction.

4. **Address the Torque Question:** The prompt specifically asks about `.tq` files. The code is `.cc`, so it's C++. The answer is straightforward: it's not a Torque file.

5. **Determine JavaScript Relevance:**  The key here is understanding the role of a "simulator" in V8. V8 needs to execute JavaScript code on different architectures. A simulator allows V8 development and testing on a non-native architecture (like x86 when the target is S390). Therefore, the code *is* related to JavaScript execution, although indirectly. It simulates the low-level behavior that a real S390 processor would exhibit when running compiled JavaScript code.

6. **Provide JavaScript Examples (Conceptual):** Since the C++ simulates assembly instructions, the direct JavaScript equivalent is less about specific syntax and more about the *operations* being performed. Think about the high-level JavaScript operations that these assembly instructions might be implementing:
    * `SRL`, `SLL`, `SRA`, `SLA`, `SRDL`, `SLDL`, `SRDA`: Bitwise shifts. JavaScript: `>>`, `<<`, `>>>` (unsigned right shift).
    * `STM`, `LM`: Memory access (storing and loading). JavaScript: Array access, object property access (which eventually involve memory operations).
    * `CLI`, `CHI`, `CGHI`, `CFI`, `CGFI`, `CLFI`, `CLGFI`: Comparisons. JavaScript: `==`, `!=`, `<`, `>`, `<=`, `>=`.
    * `MVC`: Memory copying. JavaScript:  Creating new arrays or objects by copying data.

7. **Illustrate Code Logic with Examples:** For a few selected instructions, walk through the C++ code and show how input register values and immediate values affect the output register values and flags. This requires picking instructions with relatively straightforward logic (like `SRL`, `SLL`, `SRA`, `SLA`). Clearly state the assumptions about input values.

8. **Identify Common Programming Errors:**  Think about the kinds of mistakes a programmer might make that would be related to the *effects* of these instructions.
    * **Shift Operations:** Off-by-one errors in shift amounts, misunderstanding signed vs. unsigned shifts, not masking shift amounts correctly.
    * **Memory Access:** Incorrect address calculations, buffer overflows (though the simulator might not directly *cause* these, it simulates the underlying memory operations where these could occur).
    * **Comparisons:**  Using the wrong comparison operator, not understanding how flags are set.

9. **Summarize Functionality (Part 7 Focus):**  Since this is part 7, acknowledge the ongoing nature of the analysis. Focus on the *types* of instructions covered in this specific snippet (arithmetic, logical, memory access, branching). Reiterate the simulator's role.

10. **Review and Refine:** Read through the entire analysis to ensure clarity, accuracy, and completeness. Check for any inconsistencies or areas that could be explained better. For example, ensure the JavaScript examples are conceptually accurate, even if a direct one-to-one mapping isn't possible. Ensure the input/output examples are easy to follow.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Focus on very low-level details of each instruction.
* **Correction:**  Shift the focus to the *functionality* and how it relates to higher-level concepts. Avoid getting bogged down in the minutiae of every bit manipulation unless it's crucial for understanding the core operation.
* **Initial thought:** Try to provide exact JavaScript equivalents for each instruction.
* **Correction:**  Recognize that a direct translation isn't always feasible or helpful. Focus on the *kind* of operation being simulated and how that manifests in JavaScript.
* **Initial thought:** Treat each instruction in isolation.
* **Correction:** Look for patterns and group instructions by their general purpose (arithmetic, logical, memory, control flow). This makes the summary more coherent.

By following these steps and incorporating self-correction, the analysis becomes comprehensive, addresses all aspects of the prompt, and provides a good understanding of the code's purpose within the larger V8 project.
好的，让我们来分析一下 `v8/src/execution/s390/simulator-s390.cc` 这个文件的功能。

**功能概览**

从代码结构和包含的 `EVALUATE` 宏来看，这个文件是 V8 JavaScript 引擎中用于 **模拟 IBM System/390 (s390) 架构 CPU 指令执行** 的代码。它不是真正的硬件执行器，而是一个软件模拟器，用于在非 s390 架构的机器上运行和测试为 s390 架构编译的代码。

**主要功能分解**

1. **指令解码和执行:**
   - 文件中大量的 `EVALUATE(INSTRUCTION_NAME)` 块，每个块对应一个特定的 s390 汇编指令（例如 `SRL`, `SLL`, `STM`, `LM` 等）。
   - 每个 `EVALUATE` 块内的代码负责：
     - **解码指令:**  从指令的二进制表示中提取操作数、寄存器等信息 (例如 `DECODE_RS_A_INSTRUCTION_NO_R3`, `DECODE_RI_A_INSTRUCTION` 等宏)。
     - **模拟指令行为:**  根据指令的定义，更新模拟的 CPU 寄存器、内存和状态标志（例如条件码、溢出标志）。
   - `get_register`, `set_register`, `get_low_register`, `set_low_register` 等函数用于访问和修改模拟的寄存器。
   - `ReadB`, `ReadW`, `WriteW` 等函数用于访问和修改模拟的内存。
   - `SetS390ConditionCode`, `SetS390OverflowCode` 等函数用于设置模拟的 CPU 状态标志。

2. **支持多种 s390 指令:**
   - 代码中实现了大量的 s390 指令，涵盖了算术运算、逻辑运算、移位操作、内存访问、比较、分支等多种类型。
   - 标记为 `UNIMPLEMENTED()` 的指令表示该模拟器尚未实现这些指令的功能。

3. **辅助功能:**
   - `CheckOverflowForShiftLeft`, `CheckOverflowForMul`, `CheckOverflowForIntAdd` 等函数用于辅助检测算术运算的溢出。
   - `SetS390BitWiseConditionCode` 用于设置按位运算的条件码。

**关于 .tq 结尾**

如果 `v8/src/execution/s390/simulator-s390.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码** 文件。Torque 是一种用于定义 V8 内部运行时函数的领域特定语言。由于这里是 `.cc` 结尾，所以它是 C++ 源代码，用于实现模拟器的具体逻辑。

**与 JavaScript 的关系**

`v8/src/execution/s390/simulator-s390.cc` 与 JavaScript 的执行密切相关。当 V8 需要在 s390 架构上运行 JavaScript 代码时，它会将 JavaScript 代码编译成 s390 的机器码。为了在开发、测试或某些特定环境（例如没有真实 s390 硬件的开发者机器）中执行这些 s390 机器码，就需要一个像这样的模拟器。

**JavaScript 示例 (概念性)**

虽然不能直接用一段 JavaScript 代码完全对应 `simulator-s390.cc` 的功能，但可以展示一些 JavaScript 操作，它们的底层实现可能涉及到这里模拟的 s390 指令：

```javascript
// 算术运算，可能涉及到 ADD, SUB 等指令
let a = 10;
let b = 5;
let sum = a + b; // 底层可能使用 ADD 指令

// 位运算，可能涉及到 SRL, SLL 等指令
let x = 8; // 二进制 1000
let rightShift = x >> 1; // 底层可能使用 SRL 指令

// 内存访问 (通过数组或对象)，可能涉及到 STM, LM 等指令
let arr = [1, 2, 3];
let firstElement = arr[0]; // 底层可能使用 LM 指令加载内存
arr[1] = 4; // 底层可能使用 STM 指令存储到内存

// 比较运算，可能涉及到 CLI, CHI 等指令
if (a > b) { // 底层可能使用比较指令设置条件码
  console.log("a is greater than b");
}
```

**代码逻辑推理示例**

**假设输入:**
- 模拟器执行到 `SRL` 指令，指令内容表示将寄存器 `r1` 的值右移 `shiftBits` 位。
- 寄存器 `r1` 的初始值为 `0x80000000` (十进制 -2147483648)。
- 寄存器 `b2` 的值为 `0x00000001`。
- `d2` 的值为 `1`.

**代码逻辑:**
1. `DECODE_RS_A_INSTRUCTION_NO_R3(r1, b2, d2)` 将提取操作数信息，`r1` 为目标寄存器，`b2` 和 `d2` 用于计算移位位数。
2. `uint32_t b2_val = get_low_register<uint32_t>(b2);` 获取寄存器 `b2` 的低 32 位值，即 `0x00000001`。
3. `uint32_t shiftBits = (b2_val + d2) & 0x3F;` 计算移位位数，`(0x00000001 + 1) & 0x3F` 结果为 `2`。
4. `uint32_t r1_val = get_low_register<uint32_t>(r1);` 获取寄存器 `r1` 的低 32 位值，即 `0x80000000`。
5. `alu_out = r1_val >> shiftBits;` 执行右移操作，`0x80000000 >> 2`，结果为 `0x20000000`。
6. `set_low_register(r1, alu_out);` 将结果 `0x20000000` 写入寄存器 `r1`。

**输出:**
- 寄存器 `r1` 的值变为 `0x20000000` (十进制 536870912)。

**用户常见的编程错误示例**

1. **移位位数超出范围:**
   - 在 JavaScript 中，如果右移或左移的位数超过 31 位（对于 32 位整数），或者 63 位（对于 64 位整数），其行为可能与预期不符，因为 JavaScript 会对移位位数进行模运算。
   - 在模拟器中，可以看到代码使用了 `& 0x3F` 来确保移位位数在 0-63 之间，这反映了 s390 硬件的行为。如果用户在编写模拟器时忘记进行这样的限制，就会导致模拟结果与实际硬件不符。

2. **误解有符号和无符号右移:**
   - JavaScript 中 `>>` 是有符号右移，`>>>` 是无符号右移。
   - 在 s390 指令中，`SRA` 是算术右移（保留符号位），`SRL` 是逻辑右移（补零）。
   - 用户在编写模拟器时，如果混淆了这两种右移方式，会导致负数的移位结果错误。例如，对一个负数进行逻辑右移，高位会补零，导致结果变成一个很大的正数，而算术右移则会保持符号位不变。

**第 7 部分功能归纳**

作为第 7 部分，这段代码主要展示了 **多种 s390 架构的算术、逻辑和移位指令的模拟实现**。它涵盖了：

- **基本的算术运算:**  例如加法 (`AIH`, `AFI`, `AGFI`)，乘法 (`MHI`, `MGHI`, `MSR`, `MSRKC`)，减法 (`SLFI`, `SLGFI`)。
- **逻辑运算:** 例如与 (`NILH`, `NILL`, `NIHF`, `NILF`)，或 (`OILH`, `OILL`, `OIHF`, `OILF`)，异或 (`XIHF`, `XILF`)。
- **移位操作:** 包括逻辑左移 (`SLL`, `SLDL`)，逻辑右移 (`SRL`, `SRDL`)，算术左移 (`SLA`) 和算术右移 (`SRA`, `SRDA`)。
- **比较操作:** 例如立即数比较 (`CLI`, `CHI`, `CGHI`, `CFI`, `CGFI`, `CLFI`, `CLGFI`) 和寄存器比较 (`CEBR`)。
- **加载和存储操作:** 例如加载多个寄存器 (`LM`) 和存储多个寄存器 (`STM`)。
- **分支指令:** 例如相对分支并保存返回地址 (`BRAS`, `BRASL`)，基于计数器的分支 (`BRCT`, `BRCTG`)。
- **立即数加载指令:**  例如加载立即数到寄存器 (`LHI`, `LGHI`, `LGFI`)。
- **浮点运算指令:**  例如浮点数的绝对值 (`LPEBR`), 取反 (`LCEBR`), 类型转换 (`LDEBR`), 比较 (`CEBR`), 加法 (`AEBR`), 减法 (`SEBR`), 除法 (`DEBR`), 平方根 (`SQEBR`, `SQDBR`) 等。

这些指令是构成 s390 架构程序执行的基本 building blocks。模拟器的正确实现对于 V8 在 s390 平台上的正常运行至关重要。

希望这个详细的分析能够帮助你理解 `v8/src/execution/s390/simulator-s390.cc` 文件的功能。

### 提示词
```
这是目录为v8/src/execution/s390/simulator-s390.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/s390/simulator-s390.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第7部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
return length;
}

EVALUATE(BXLE) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SRL) {
  DCHECK_OPCODE(SRL);
  DECODE_RS_A_INSTRUCTION_NO_R3(r1, b2, d2);
  // only takes rightmost 6bits
  uint32_t b2_val = b2 == 0 ? 0 : get_low_register<uint32_t>(b2);
  uint32_t shiftBits = (b2_val + d2) & 0x3F;
  uint32_t r1_val = get_low_register<uint32_t>(r1);
  uint32_t alu_out = 0;
  if (shiftBits < 32u) {
    alu_out = r1_val >> shiftBits;
  }
  set_low_register(r1, alu_out);
  return length;
}

EVALUATE(SLL) {
  DCHECK_OPCODE(SLL);
  DECODE_RS_A_INSTRUCTION_NO_R3(r1, b2, d2)
  // only takes rightmost 6bits
  uint32_t b2_val = b2 == 0 ? 0 : get_low_register<uint32_t>(b2);
  uint32_t shiftBits = (b2_val + d2) & 0x3F;
  uint32_t r1_val = get_low_register<uint32_t>(r1);
  uint32_t alu_out = 0;
  if (shiftBits < 32u) {
    alu_out = r1_val << shiftBits;
  }
  set_low_register(r1, alu_out);
  return length;
}

EVALUATE(SRA) {
  DCHECK_OPCODE(SRA);
  DECODE_RS_A_INSTRUCTION_NO_R3(r1, b2, d2);
  // only takes rightmost 6bits
  int64_t b2_val = b2 == 0 ? 0 : get_register(b2);
  int shiftBits = (b2_val + d2) & 0x3F;
  int32_t r1_val = get_low_register<int32_t>(r1);
  int32_t alu_out = -1;
  bool isOF = false;
  if (shiftBits < 32) {
    alu_out = r1_val >> shiftBits;
  }
  set_low_register(r1, alu_out);
  SetS390ConditionCode<int32_t>(alu_out, 0);
  SetS390OverflowCode(isOF);
  return length;
}

EVALUATE(SLA) {
  DCHECK_OPCODE(SLA);
  DECODE_RS_A_INSTRUCTION_NO_R3(r1, b2, d2);
  // only takes rightmost 6bits
  int64_t b2_val = b2 == 0 ? 0 : get_register(b2);
  int shiftBits = (b2_val + d2) & 0x3F;
  int32_t r1_val = get_low_register<int32_t>(r1);
  int32_t alu_out = 0;
  bool isOF = false;
  isOF = CheckOverflowForShiftLeft(r1_val, shiftBits);
  if (shiftBits < 32) {
    alu_out = r1_val << shiftBits;
  }
  set_low_register(r1, alu_out);
  SetS390ConditionCode<int32_t>(alu_out, 0);
  SetS390OverflowCode(isOF);
  return length;
}

EVALUATE(SRDL) {
  DCHECK_OPCODE(SRDL);
  DECODE_RS_A_INSTRUCTION_NO_R3(r1, b2, d2);
  DCHECK_EQ(r1 % 2, 0);  // must be a reg pair
  // only takes rightmost 6bits
  int64_t b2_val = b2 == 0 ? 0 : get_register(b2);
  int shiftBits = (b2_val + d2) & 0x3F;
  uint64_t opnd1 = static_cast<uint64_t>(get_low_register<uint32_t>(r1)) << 32;
  uint64_t opnd2 = static_cast<uint64_t>(get_low_register<uint32_t>(r1 + 1));
  uint64_t r1_val = opnd1 | opnd2;
  uint64_t alu_out = r1_val >> shiftBits;
  set_low_register(r1, alu_out >> 32);
  set_low_register(r1 + 1, alu_out & 0x00000000FFFFFFFF);
  SetS390ConditionCode<int32_t>(alu_out, 0);
  return length;
}

EVALUATE(SLDL) {
  DCHECK_OPCODE(SLDL);
  DECODE_RS_A_INSTRUCTION_NO_R3(r1, b2, d2);
  // only takes rightmost 6bits
  int64_t b2_val = b2 == 0 ? 0 : get_register(b2);
  int shiftBits = (b2_val + d2) & 0x3F;

  DCHECK_EQ(r1 % 2, 0);
  uint32_t r1_val = get_low_register<uint32_t>(r1);
  uint32_t r1_next_val = get_low_register<uint32_t>(r1 + 1);
  uint64_t alu_out = (static_cast<uint64_t>(r1_val) << 32) |
                     (static_cast<uint64_t>(r1_next_val));
  alu_out <<= shiftBits;
  set_low_register(r1 + 1, static_cast<uint32_t>(alu_out));
  set_low_register(r1, static_cast<uint32_t>(alu_out >> 32));
  return length;
}

EVALUATE(SRDA) {
  DCHECK_OPCODE(SRDA);
  DECODE_RS_A_INSTRUCTION_NO_R3(r1, b2, d2);
  DCHECK_EQ(r1 % 2, 0);  // must be a reg pair
  // only takes rightmost 6bits
  int64_t b2_val = b2 == 0 ? 0 : get_register(b2);
  int shiftBits = (b2_val + d2) & 0x3F;
  int64_t opnd1 = static_cast<int64_t>(get_low_register<int32_t>(r1)) << 32;
  int64_t opnd2 = static_cast<uint64_t>(get_low_register<uint32_t>(r1 + 1));
  int64_t r1_val = opnd1 + opnd2;
  int64_t alu_out = r1_val >> shiftBits;
  set_low_register(r1, alu_out >> 32);
  set_low_register(r1 + 1, alu_out & 0x00000000FFFFFFFF);
  SetS390ConditionCode<int32_t>(alu_out, 0);
  return length;
}

EVALUATE(SLDA) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(STM) {
  DCHECK_OPCODE(STM);
  DECODE_RS_A_INSTRUCTION(r1, r3, rb, d2);
  // Store Multiple 32-bits.
  int offset = d2;
  // Regs roll around if r3 is less than r1.
  // Artificially increase r3 by 16 so we can calculate
  // the number of regs stored properly.
  if (r3 < r1) r3 += 16;

  int32_t rb_val = (rb == 0) ? 0 : get_low_register<int32_t>(rb);

  // Store each register in ascending order.
  for (int i = 0; i <= r3 - r1; i++) {
    int32_t value = get_low_register<int32_t>((r1 + i) % 16);
    WriteW(rb_val + offset + 4 * i, value);
  }
  return length;
}

EVALUATE(MVI) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(TS) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(NI) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CLI) {
  DCHECK_OPCODE(CLI);
  // Compare Immediate (Mem - Imm) (8)
  DECODE_SI_INSTRUCTION_I_UINT8(b1, d1_val, imm_val)
  int64_t b1_val = (b1 == 0) ? 0 : get_register(b1);
  intptr_t addr = b1_val + d1_val;
  uint8_t mem_val = ReadB(addr);
  SetS390ConditionCode<uint8_t>(mem_val, imm_val);
  return length;
}

EVALUATE(OI) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(XI) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LM) {
  DCHECK_OPCODE(LM);
  DECODE_RS_A_INSTRUCTION(r1, r3, rb, d2);
  // Store Multiple 32-bits.
  int offset = d2;
  // Regs roll around if r3 is less than r1.
  // Artificially increase r3 by 16 so we can calculate
  // the number of regs stored properly.
  if (r3 < r1) r3 += 16;

  int32_t rb_val = (rb == 0) ? 0 : get_low_register<int32_t>(rb);

  // Store each register in ascending order.
  for (int i = 0; i <= r3 - r1; i++) {
    int32_t value = ReadW(rb_val + offset + 4 * i);
    set_low_register((r1 + i) % 16, value);
  }
  return length;
}

EVALUATE(MVCLE) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CLCLE) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(MC) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CDS) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(STCM) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(ICM) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(BPRP) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(BPP) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(TRTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(MVN) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(MVC) {
  DCHECK_OPCODE(MVC);
  // Move Character
  SSInstruction* ssInstr = reinterpret_cast<SSInstruction*>(instr);
  int b1 = ssInstr->B1Value();
  intptr_t d1 = ssInstr->D1Value();
  int b2 = ssInstr->B2Value();
  intptr_t d2 = ssInstr->D2Value();
  int length = ssInstr->Length();
  int64_t b1_val = (b1 == 0) ? 0 : get_register(b1);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  intptr_t src_addr = b2_val + d2;
  intptr_t dst_addr = b1_val + d1;
  // remember that the length is the actual length - 1
  for (int i = 0; i < length + 1; ++i) {
    WriteB(dst_addr++, ReadB(src_addr++));
  }
  length = 6;
  return length;
}

EVALUATE(MVZ) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(NC) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CLC) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(OC) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(XC) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(MVCP) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(TR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(TRT) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(ED) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(EDMK) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(PKU) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(UNPKU) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(MVCIN) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(PKA) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(UNPKA) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(PLO) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LMD) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SRP) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(MVO) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(PACK) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(UNPK) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(ZAP) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(AP) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SP) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(MP) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(DP) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(UPT) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(PFPO) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(IIHH) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(IIHL) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(IILH) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(IILL) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(NIHH) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(NIHL) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(NILH) {
  DCHECK_OPCODE(NILH);
  DECODE_RI_A_INSTRUCTION(instr, r1, i);
  int32_t r1_val = get_low_register<int32_t>(r1);
  // CC is set based on the 16 bits that are AND'd
  SetS390BitWiseConditionCode<uint16_t>((r1_val >> 16) & i);
  i = (i << 16) | 0x0000FFFF;
  set_low_register(r1, r1_val & i);
  return length;
}

EVALUATE(NILL) {
  DCHECK_OPCODE(NILL);
  DECODE_RI_A_INSTRUCTION(instr, r1, i);
  int32_t r1_val = get_low_register<int32_t>(r1);
  // CC is set based on the 16 bits that are AND'd
  SetS390BitWiseConditionCode<uint16_t>(r1_val & i);
  i |= 0xFFFF0000;
  set_low_register(r1, r1_val & i);
  return length;
}

EVALUATE(OIHH) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(OIHL) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(OILH) {
  DCHECK_OPCODE(OILH);
  DECODE_RI_A_INSTRUCTION(instr, r1, i);
  int32_t r1_val = get_low_register<int32_t>(r1);
  // CC is set based on the 16 bits that are AND'd
  SetS390BitWiseConditionCode<uint16_t>((r1_val >> 16) | i);
  i = i << 16;
  set_low_register(r1, r1_val | i);
  return length;
}

EVALUATE(OILL) {
  DCHECK_OPCODE(OILL);
  DECODE_RI_A_INSTRUCTION(instr, r1, i);
  int32_t r1_val = get_low_register<int32_t>(r1);
  // CC is set based on the 16 bits that are AND'd
  SetS390BitWiseConditionCode<uint16_t>(r1_val | i);
  set_low_register(r1, r1_val | i);
  return length;
}

EVALUATE(LLIHH) {
  DCHECK_OPCODE(LLIHL);
  DECODE_RI_A_INSTRUCTION(instr, r1, i2);
  uint64_t imm = static_cast<uint64_t>(i2) & 0xffff;
  set_register(r1, imm << 48);
  return length;
}

EVALUATE(LLIHL) {
  DCHECK_OPCODE(LLIHL);
  DECODE_RI_A_INSTRUCTION(instr, r1, i2);
  uint64_t imm = static_cast<uint64_t>(i2) & 0xffff;
  set_register(r1, imm << 32);
  return length;
}

EVALUATE(LLILH) {
  DCHECK_OPCODE(LLILH);
  DECODE_RI_A_INSTRUCTION(instr, r1, i2);
  uint64_t imm = static_cast<uint64_t>(i2) & 0xffff;
  set_register(r1, imm << 16);
  return length;
}

EVALUATE(LLILL) {
  DCHECK_OPCODE(LLILL);
  DECODE_RI_A_INSTRUCTION(instr, r1, i2);
  uint64_t imm = static_cast<uint64_t>(i2) & 0xffff;
  set_register(r1, imm);
  return length;
}

inline static int TestUnderMask(uint16_t val, uint16_t mask,
                                bool is_tm_or_tmy) {
  // Test if all selected bits are zeros or mask is zero
  if (0 == (mask & val)) {
    return 0x8;
  }

  // Test if all selected bits are one or mask is 0
  if (mask == (mask & val)) {
    return 0x1;
  }

  // Now we know selected bits mixed zeros and ones
  // Test if it is TM or TMY since they have
  // different CC result from TMLL/TMLH/TMHH/TMHL
  if (is_tm_or_tmy) {
    return 0x4;
  }

  // Now we know the instruction is TMLL/TMLH/TMHH/TMHL
  // Test if the leftmost bit is zero or one
#if defined(__GNUC__)
  int leadingZeros = __builtin_clz(mask);
  mask = 0x80000000u >> leadingZeros;
  if (mask & val) {
    // leftmost bit is one
    return 0x2;
  } else {
    // leftmost bit is zero
    return 0x4;
  }
#else
  for (int i = 15; i >= 0; i--) {
    if (mask & (1 << i)) {
      if (val & (1 << i)) {
        // leftmost bit is one
        return 0x2;
      } else {
        // leftmost bit is zero
        return 0x4;
      }
    }
  }
#endif
  UNREACHABLE();
}

EVALUATE(TMLH) {
  DCHECK_OPCODE(TMLH);
  DECODE_RI_A_INSTRUCTION(instr, r1, i2);
  uint32_t value = get_low_register<uint32_t>(r1) >> 16;
  uint32_t mask = i2 & 0x0000FFFF;
  bool is_tm_or_tmy = 0;
  condition_reg_ = TestUnderMask(value, mask, is_tm_or_tmy);
  return length;  // DONE
}

EVALUATE(TMLL) {
  DCHECK_OPCODE(TMLL);
  DECODE_RI_A_INSTRUCTION(instr, r1, i2);
  uint32_t value = get_low_register<uint32_t>(r1) & 0x0000FFFF;
  uint32_t mask = i2 & 0x0000FFFF;
  bool is_tm_or_tmy = 0;
  condition_reg_ = TestUnderMask(value, mask, is_tm_or_tmy);
  return length;  // DONE
}

EVALUATE(TMHH) {
  DCHECK_OPCODE(TMHH);
  DECODE_RI_A_INSTRUCTION(instr, r1, i2);
  uint32_t value = get_high_register<uint32_t>(r1) >> 16;
  uint32_t mask = i2 & 0x0000FFFF;
  bool is_tm_or_tmy = 0;
  condition_reg_ = TestUnderMask(value, mask, is_tm_or_tmy);
  return length;
}

EVALUATE(TMHL) {
  DCHECK_OPCODE(TMHL);
  DECODE_RI_A_INSTRUCTION(instr, r1, i2);
  uint32_t value = get_high_register<uint32_t>(r1) & 0x0000FFFF;
  uint32_t mask = i2 & 0x0000FFFF;
  bool is_tm_or_tmy = 0;
  condition_reg_ = TestUnderMask(value, mask, is_tm_or_tmy);
  return length;
}

EVALUATE(BRAS) {
  DCHECK_OPCODE(BRAS);
  // Branch Relative and Save
  DECODE_RI_B_INSTRUCTION(instr, r1, d2)
  intptr_t pc = get_pc();
  // Set PC of next instruction to register
  set_register(r1, pc + sizeof(FourByteInstr));
  // Update PC to branch target
  set_pc(pc + d2 * 2);
  return length;
}

EVALUATE(BRCT) {
  DCHECK_OPCODE(BRCT);
  // Branch On Count (32/64).
  DECODE_RI_A_INSTRUCTION(instr, r1, i2);
  int64_t value = get_low_register<int32_t>(r1);
  set_low_register(r1, --value);
  // Branch if value != 0
  if (value != 0) {
    intptr_t offset = i2 * 2;
    set_pc(get_pc() + offset);
  }
  return length;
}

EVALUATE(BRCTG) {
  DCHECK_OPCODE(BRCTG);
  // Branch On Count (32/64).
  DECODE_RI_A_INSTRUCTION(instr, r1, i2);
  int64_t value = get_register(r1);
  set_register(r1, --value);
  // Branch if value != 0
  if (value != 0) {
    intptr_t offset = i2 * 2;
    set_pc(get_pc() + offset);
  }
  return length;
}

EVALUATE(LHI) {
  DCHECK_OPCODE(LHI);
  DECODE_RI_A_INSTRUCTION(instr, r1, i);
  set_low_register(r1, i);
  return length;
}

EVALUATE(LGHI) {
  DCHECK_OPCODE(LGHI);
  DECODE_RI_A_INSTRUCTION(instr, r1, i2);
  int64_t i = static_cast<int64_t>(i2);
  set_register(r1, i);
  return length;
}

EVALUATE(MHI) {
  DCHECK_OPCODE(MHI);
  DECODE_RI_A_INSTRUCTION(instr, r1, i);
  int32_t r1_val = get_low_register<int32_t>(r1);
  bool isOF = false;
  isOF = CheckOverflowForMul(r1_val, i);
  r1_val *= i;
  set_low_register(r1, r1_val);
  SetS390ConditionCode<int32_t>(r1_val, 0);
  SetS390OverflowCode(isOF);
  return length;
}

EVALUATE(MGHI) {
  DCHECK_OPCODE(MGHI);
  DECODE_RI_A_INSTRUCTION(instr, r1, i2);
  int64_t i = static_cast<int64_t>(i2);
  int64_t r1_val = get_register(r1);
  bool isOF = false;
  isOF = CheckOverflowForMul(r1_val, i);
  r1_val *= i;
  set_register(r1, r1_val);
  SetS390ConditionCode<int32_t>(r1_val, 0);
  SetS390OverflowCode(isOF);
  return length;
}

EVALUATE(CHI) {
  DCHECK_OPCODE(CHI);
  DECODE_RI_A_INSTRUCTION(instr, r1, i);
  int32_t r1_val = get_low_register<int32_t>(r1);
  SetS390ConditionCode<int32_t>(r1_val, i);
  return length;
}

EVALUATE(CGHI) {
  DCHECK_OPCODE(CGHI);
  DECODE_RI_A_INSTRUCTION(instr, r1, i2);
  int64_t i = static_cast<int64_t>(i2);
  int64_t r1_val = get_register(r1);
  SetS390ConditionCode<int64_t>(r1_val, i);
  return length;
}

EVALUATE(LARL) {
  DCHECK_OPCODE(LARL);
  DECODE_RIL_B_INSTRUCTION(r1, i2);
  intptr_t offset = i2 * 2;
  set_register(r1, get_pc() + offset);
  return length;
}

EVALUATE(LGFI) {
  DCHECK_OPCODE(LGFI);
  DECODE_RIL_A_INSTRUCTION(r1, imm);
  set_register(r1, static_cast<int64_t>(static_cast<int32_t>(imm)));
  return length;
}

EVALUATE(BRASL) {
  DCHECK_OPCODE(BRASL);
  // Branch and Save Relative Long
  DECODE_RIL_B_INSTRUCTION(r1, i2);
  intptr_t d2 = i2;
  intptr_t pc = get_pc();
  set_register(r1, pc + 6);  // save next instruction to register
  set_pc(pc + d2 * 2);       // update register
  return length;
}

EVALUATE(XIHF) {
  DCHECK_OPCODE(XIHF);
  DECODE_RIL_A_INSTRUCTION(r1, imm);
  uint32_t alu_out = 0;
  alu_out = get_high_register<uint32_t>(r1);
  alu_out = alu_out ^ imm;
  set_high_register(r1, alu_out);
  SetS390BitWiseConditionCode<uint32_t>(alu_out);
  return length;
}

EVALUATE(XILF) {
  DCHECK_OPCODE(XILF);
  DECODE_RIL_A_INSTRUCTION(r1, imm);
  uint32_t alu_out = 0;
  alu_out = get_low_register<uint32_t>(r1);
  alu_out = alu_out ^ imm;
  set_low_register(r1, alu_out);
  SetS390BitWiseConditionCode<uint32_t>(alu_out);
  return length;
}

EVALUATE(NIHF) {
  DCHECK_OPCODE(NIHF);
  // Bitwise Op on upper 32-bits
  DECODE_RIL_A_INSTRUCTION(r1, imm);
  uint32_t alu_out = get_high_register<uint32_t>(r1);
  alu_out &= imm;
  SetS390BitWiseConditionCode<uint32_t>(alu_out);
  set_high_register(r1, alu_out);
  return length;
}

EVALUATE(NILF) {
  DCHECK_OPCODE(NILF);
  // Bitwise Op on lower 32-bits
  DECODE_RIL_A_INSTRUCTION(r1, imm);
  uint32_t alu_out = get_low_register<uint32_t>(r1);
  alu_out &= imm;
  SetS390BitWiseConditionCode<uint32_t>(alu_out);
  set_low_register(r1, alu_out);
  return length;
}

EVALUATE(OIHF) {
  DCHECK_OPCODE(OIHF);
  // Bitwise Op on upper 32-bits
  DECODE_RIL_B_INSTRUCTION(r1, imm);
  uint32_t alu_out = get_high_register<uint32_t>(r1);
  alu_out |= imm;
  SetS390BitWiseConditionCode<uint32_t>(alu_out);
  set_high_register(r1, alu_out);
  return length;
}

EVALUATE(OILF) {
  DCHECK_OPCODE(OILF);
  // Bitwise Op on lower 32-bits
  DECODE_RIL_B_INSTRUCTION(r1, imm);
  uint32_t alu_out = get_low_register<uint32_t>(r1);
  alu_out |= imm;
  SetS390BitWiseConditionCode<uint32_t>(alu_out);
  set_low_register(r1, alu_out);
  return length;
}

EVALUATE(LLIHF) {
  DCHECK_OPCODE(LLIHF);
  // Load Logical Immediate into high word
  DECODE_RIL_A_INSTRUCTION(r1, i2);
  uint64_t imm = static_cast<uint64_t>(i2);
  set_register(r1, imm << 32);
  return length;
}

EVALUATE(LLILF) {
  DCHECK_OPCODE(LLILF);
  // Load Logical into lower 32-bits (zero extend upper 32-bits)
  DECODE_RIL_A_INSTRUCTION(r1, i2);
  uint64_t imm = static_cast<uint64_t>(i2);
  set_register(r1, imm);
  return length;
}

EVALUATE(MSGFI) {
  DCHECK_OPCODE(MSGFI);
  DECODE_RIL_B_INSTRUCTION(r1, i2);
  int64_t alu_out = get_register(r1);
  alu_out = alu_out * i2;
  set_register(r1, alu_out);
  return length;
}

EVALUATE(MSFI) {
  DCHECK_OPCODE(MSFI);
  DECODE_RIL_B_INSTRUCTION(r1, i2);
  int32_t alu_out = get_low_register<int32_t>(r1);
  alu_out = alu_out * i2;
  set_low_register(r1, alu_out);
  return length;
}

EVALUATE(SLGFI) {
  DCHECK_OPCODE(SLGFI);
  DECODE_RIL_A_INSTRUCTION(r1, i2);
  uint64_t r1_val = (uint64_t)(get_register(r1));
  uint64_t alu_out;
  alu_out = r1_val - i2;
  set_register(r1, (intptr_t)alu_out);
  SetS390ConditionCode<uint64_t>(alu_out, 0);
  return length;
}

EVALUATE(SLFI) {
  DCHECK_OPCODE(SLFI);
  DECODE_RIL_A_INSTRUCTION(r1, imm);
  uint32_t alu_out = get_low_register<uint32_t>(r1);
  alu_out -= imm;
  SetS390ConditionCode<uint32_t>(alu_out, 0);
  set_low_register(r1, alu_out);
  return length;
}

EVALUATE(AGFI) {
  DCHECK_OPCODE(AGFI);
  // Clobbering Add Word Immediate
  DECODE_RIL_B_INSTRUCTION(r1, i2_val);
  bool isOF = false;
  // 64-bit Add (Register + 32-bit Imm)
  int64_t r1_val = get_register(r1);
  int64_t i2 = static_cast<int64_t>(i2_val);
  isOF = CheckOverflowForIntAdd(r1_val, i2, int64_t);
  int64_t alu_out = r1_val + i2;
  set_register(r1, alu_out);
  SetS390ConditionCode<int64_t>(alu_out, 0);
  SetS390OverflowCode(isOF);
  return length;
}

EVALUATE(AFI) {
  DCHECK_OPCODE(AFI);
  // Clobbering Add Word Immediate
  DECODE_RIL_B_INSTRUCTION(r1, i2);
  bool isOF = false;
  // 32-bit Add (Register + 32-bit Immediate)
  int32_t r1_val = get_low_register<int32_t>(r1);
  isOF = CheckOverflowForIntAdd(r1_val, i2, int32_t);
  int32_t alu_out = r1_val + i2;
  set_low_register(r1, alu_out);
  SetS390ConditionCode<int32_t>(alu_out, 0);
  SetS390OverflowCode(isOF);
  return length;
}

EVALUATE(ALGFI) {
  DCHECK_OPCODE(ALGFI);
  DECODE_RIL_A_INSTRUCTION(r1, i2);
  uint64_t r1_val = (uint64_t)(get_register(r1));
  uint64_t alu_out;
  alu_out = r1_val + i2;
  set_register(r1, (intptr_t)alu_out);
  SetS390ConditionCode<uint64_t>(alu_out, 0);

  return length;
}

EVALUATE(ALFI) {
  DCHECK_OPCODE(ALFI);
  DECODE_RIL_A_INSTRUCTION(r1, imm);
  uint32_t alu_out = get_low_register<uint32_t>(r1);
  alu_out += imm;
  SetS390ConditionCode<uint32_t>(alu_out, 0);
  set_low_register(r1, alu_out);
  return length;
}

EVALUATE(CGFI) {
  DCHECK_OPCODE(CGFI);
  // Compare with Immediate (64)
  DECODE_RIL_B_INSTRUCTION(r1, i2);
  int64_t imm = static_cast<int64_t>(i2);
  SetS390ConditionCode<int64_t>(get_register(r1), imm);
  return length;
}

EVALUATE(CFI) {
  DCHECK_OPCODE(CFI);
  // Compare with Immediate (32)
  DECODE_RIL_B_INSTRUCTION(r1, imm);
  SetS390ConditionCode<int32_t>(get_low_register<int32_t>(r1), imm);
  return length;
}

EVALUATE(CLGFI) {
  DCHECK_OPCODE(CLGFI);
  // Compare Logical with Immediate (64)
  DECODE_RIL_A_INSTRUCTION(r1, i2);
  uint64_t imm = static_cast<uint64_t>(i2);
  SetS390ConditionCode<uint64_t>(get_register(r1), imm);
  return length;
}

EVALUATE(CLFI) {
  DCHECK_OPCODE(CLFI);
  // Compare Logical with Immediate (32)
  DECODE_RIL_A_INSTRUCTION(r1, imm);
  SetS390ConditionCode<uint32_t>(get_low_register<uint32_t>(r1), imm);
  return length;
}

EVALUATE(LLHRL) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LGHRL) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LHRL) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LLGHRL) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(STHRL) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LGRL) {
  DCHECK_OPCODE(LGRL);
  DECODE_RIL_B_INSTRUCTION(r1, i2);
  intptr_t offset = i2 * 2;
  int64_t mem_val = ReadDW(get_pc() + offset);
  set_register(r1, mem_val);
  return length;
}

EVALUATE(STGRL) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LGFRL) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LRL) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LLGFRL) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(STRL) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(EXRL) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(PFDRL) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CGHRL) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CHRL) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CGRL) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CGFRL) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(ECTG) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CSST) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LPD) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LPDG) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(BRCTH) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(AIH) {
  DCHECK_OPCODE(AIH);
  DECODE_RIL_A_INSTRUCTION(r1, i2);
  int32_t r1_val = get_high_register<int32_t>(r1);
  bool isOF = CheckOverflowForIntAdd(r1_val, static_cast<int32_t>(i2), int32_t);
  r1_val += static_cast<int32_t>(i2);
  set_high_register(r1, r1_val);
  SetS390ConditionCode<int32_t>(r1_val, 0);
  SetS390OverflowCode(isOF);
  return length;
}

EVALUATE(ALSIH) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(ALSIHN) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CIH) {
  DCHECK_OPCODE(CIH);
  DECODE_RIL_A_INSTRUCTION(r1, imm);
  int32_t r1_val = get_high_register<int32_t>(r1);
  SetS390ConditionCode<int32_t>(r1_val, static_cast<int32_t>(imm));
  return length;
}

EVALUATE(CLIH) {
  DCHECK_OPCODE(CLIH);
  // Compare Logical with Immediate (32)
  DECODE_RIL_A_INSTRUCTION(r1, imm);
  SetS390ConditionCode<uint32_t>(get_high_register<uint32_t>(r1), imm);
  return length;
}

EVALUATE(STCK) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CFC) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(IPM) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(HSCH) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(MSCH) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SSCH) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(STSCH) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(TSCH) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(TPI) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SAL) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(RSCH) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(STCRW) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(STCPS) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(RCHP) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SCHM) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CKSM) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SAR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(EAR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(MSR) {
  DCHECK_OPCODE(MSR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  int32_t r1_val = get_low_register<int32_t>(r1);
  int32_t r2_val = get_low_register<int32_t>(r2);
  set_low_register(r1, r1_val * r2_val);
  return length;
}

EVALUATE(MSRKC) {
  DCHECK_OPCODE(MSRKC);
  DECODE_RRF_A_INSTRUCTION(r1, r2, r3);
  int32_t r2_val = get_low_register<int32_t>(r2);
  int32_t r3_val = get_low_register<int32_t>(r3);
  int64_t result64 =
      static_cast<int64_t>(r2_val) * static_cast<int64_t>(r3_val);
  int32_t result32 = static_cast<int32_t>(result64);
  bool isOF = (static_cast<int64_t>(result32) != result64);
  SetS390ConditionCode<int32_t>(result32, 0);
  SetS390OverflowCode(isOF);
  set_low_register(r1, result32);
  return length;
}

EVALUATE(MVST) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CUSE) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SRST) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(XSCH) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(STCKE) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(STCKF) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SRNM) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(STFPC) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LFPC) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(TRE) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(STFLE) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SRNMB) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SRNMT) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LFAS) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(PPA) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(ETND) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(TEND) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(NIAI) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(TABORT) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(TRAP4) {
  DCHECK_OPCODE(TRAP4);
  int length = 4;
  // whack the space of the caller allocated stack
  int64_t sp_addr = get_register(sp);
  for (int i = 0; i < kCalleeRegisterSaveAreaSize / kSystemPointerSize; ++i) {
    // we dont want to whack the RA (r14)
    if (i != 14) (reinterpret_cast<intptr_t*>(sp_addr))[i] = 0xDEADBABE;
  }
  SoftwareInterrupt(instr);
  return length;
}

EVALUATE(LPEBR) {
  DCHECK_OPCODE(LPEBR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  float fr1_val = get_fpr<float>(r1);
  float fr2_val = get_fpr<float>(r2);
  fr1_val = std::fabs(fr2_val);
  set_fpr(r1, fr1_val);
  if (fr2_val != fr2_val) {  // input is NaN
    condition_reg_ = CC_OF;
  } else if (fr2_val == 0) {
    condition_reg_ = CC_EQ;
  } else {
    condition_reg_ = CC_GT;
  }

  return length;
}

EVALUATE(LNEBR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LTEBR) {
  DCHECK_OPCODE(LTEBR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  int64_t r2_val = get_fpr<int64_t>(r2);
  float fr2_val = get_fpr<float>(r2);
  SetS390ConditionCode<float>(fr2_val, 0.0);
  set_fpr(r1, r2_val);
  return length;
}

EVALUATE(LCEBR) {
  DCHECK_OPCODE(LCEBR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  float fr1_val = get_fpr<float>(r1);
  float fr2_val = get_fpr<float>(r2);
  fr1_val = -fr2_val;
  set_fpr(r1, fr1_val);
  if (fr2_val != fr2_val) {  // input is NaN
    condition_reg_ = CC_OF;
  } else if (fr2_val == 0) {
    condition_reg_ = CC_EQ;
  } else if (fr2_val < 0) {
    condition_reg_ = CC_LT;
  } else if (fr2_val > 0) {
    condition_reg_ = CC_GT;
  }
  return length;
}

EVALUATE(LDEBR) {
  DCHECK_OPCODE(LDEBR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  float fp_val = get_fpr<float>(r2);
  double db_val = static_cast<double>(fp_val);
  set_fpr(r1, db_val);
  return length;
}

EVALUATE(LXDBR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LXEBR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(MXDBR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(KEBR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CEBR) {
  DCHECK_OPCODE(CEBR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  float fr1_val = get_fpr<float>(r1);
  float fr2_val = get_fpr<float>(r2);
  if (isNaN(fr1_val) || isNaN(fr2_val)) {
    condition_reg_ = CC_OF;
  } else {
    SetS390ConditionCode<float>(fr1_val, fr2_val);
  }

  return length;
}

EVALUATE(AEBR) {
  DCHECK_OPCODE(AEBR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  float fr1_val = get_fpr<float>(r1);
  float fr2_val = get_fpr<float>(r2);
  fr1_val += fr2_val;
  set_fpr(r1, fr1_val);
  SetS390ConditionCode<float>(fr1_val, 0);

  return length;
}

EVALUATE(SEBR) {
  DCHECK_OPCODE(SEBR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  float fr1_val = get_fpr<float>(r1);
  float fr2_val = get_fpr<float>(r2);
  fr1_val -= fr2_val;
  set_fpr(r1, fr1_val);
  SetS390ConditionCode<float>(fr1_val, 0);

  return length;
}

EVALUATE(MDEBR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(DEBR) {
  DCHECK_OPCODE(DEBR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  float fr1_val = get_fpr<float>(r1);
  float fr2_val = get_fpr<float>(r2);
  fr1_val /= fr2_val;
  set_fpr(r1, fr1_val);
  return length;
}

EVALUATE(MAEBR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(MSEBR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LPDBR) {
  DCHECK_OPCODE(LPDBR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  double r1_val = get_fpr<double>(r1);
  double r2_val = get_fpr<double>(r2);
  r1_val = std::fabs(r2_val);
  set_fpr(r1, r1_val);
  if (r2_val != r2_val) {  // input is NaN
    condition_reg_ = CC_OF;
  } else if (r2_val == 0) {
    condition_reg_ = CC_EQ;
  } else {
    condition_reg_ = CC_GT;
  }
  return length;
}

EVALUATE(LNDBR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LTDBR) {
  DCHECK_OPCODE(LTDBR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  int64_t r2_val = get_fpr<int64_t>(r2);
  SetS390ConditionCode<double>(base::bit_cast<double, int64_t>(r2_val), 0.0);
  set_fpr(r1, r2_val);
  return length;
}

EVALUATE(LCDBR) {
  DCHECK_OPCODE(LCDBR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  double r1_val = get_fpr<double>(r1);
  double r2_val = get_fpr<double>(r2);
  r1_val = -r2_val;
  set_fpr(r1, r1_val);
  if (r2_val != r2_val) {  // input is NaN
    condition_reg_ = CC_OF;
  } else if (r2_val == 0) {
    condition_reg_ = CC_EQ;
  } else if (r2_val < 0) {
    condition_reg_ = CC_LT;
  } else if (r2_val > 0) {
    condition_reg_ = CC_GT;
  }
  return length;
}

EVALUATE(SQEBR) {
  DCHECK_OPCODE(SQEBR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  float fr1_val = get_fpr<float>(r1);
  float fr2_val = get_fpr<float>(r2);
  fr1_val = std::sqrt(fr2_val);
  set_fpr(r1, fr1_val);
  return length;
}

EVALUATE(SQDBR) {
  DCHECK_OPCODE(SQDBR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  double r1_val = get_fpr<double>(r1);
  double r2_val = get_fpr<double>(r2);
  r1_val = std::sqrt(r2_val);
  set_fpr(r1, r1_val);
  return length;
}

EVALUATE(SQXBR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(MEEBR) {
  DCHECK_OPCODE(MEEBR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  float fr1_val = get_fpr<float>(r1);
  float fr2_val = get_fpr<float>(r2);
  fr1_val *= fr2_val;
  set_fpr(r1, fr1_val);
  return length;
}

EVALUATE(KDBR) {
  UNIMPLEMENT
```