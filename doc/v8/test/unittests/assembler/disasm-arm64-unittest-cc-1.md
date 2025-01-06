Response:
The user wants me to analyze a C++ source code file for V8, specifically `v8/test/unittests/assembler/disasm-arm64-unittest.cc`.

Here's a breakdown of the thought process to address the request:

1. **Identify the file type and purpose:** The `.cc` extension indicates a C++ source file. The path `v8/test/unittests/assembler/` suggests this file contains unit tests related to the assembler component of V8. The `disasm-arm64-unittest` part strongly suggests these tests are specifically for the ARM64 architecture's disassembler. Disassemblers convert machine code back into assembly language.

2. **Determine the core functionality:** Based on the name, the primary function is testing the ARM64 disassembler in V8. The code snippets within the `TEST_F` macros confirm this. Each test case sets up an assembler, generates some ARM64 instructions, and then uses a `COMPARE` macro to check if the disassembler produces the expected assembly string.

3. **Check for Torque involvement:** The prompt asks about `.tq` files. This file is `.cc`, so it's not a Torque file.

4. **Assess JavaScript relevance:** Disassemblers work on machine code, which is the output of a compiler or assembler. While JavaScript code *eventually* gets compiled to machine code that *could* be disassembled, this unit test directly tests the disassembler's ability to handle specific ARM64 instruction patterns. It doesn't directly test the interaction with JavaScript code. However, the disassembler is a tool used in the V8 JavaScript engine, particularly for debugging and code inspection. Therefore, there's an *indirect* relationship.

5. **Provide JavaScript examples (if relevant):** Since the connection is indirect, illustrating with JavaScript would be about showing how the disassembler *might* be used in a debugging scenario. For instance, if you have a crash in JIT-compiled code, the disassembler could help understand the generated machine code.

6. **Look for code logic and inference:** The tests are structured around comparing expected disassembler output with the actual output for various ARM64 instructions. The logic is in how the ARM64 instructions are constructed and the expected assembly format. To demonstrate this, we can pick a specific test case and show the input (the instruction being assembled) and the expected output (the disassembled string).

7. **Identify common programming errors:**  Since this is a testing file, it doesn't directly *demonstrate* user programming errors. However, we can infer the kind of errors that testing a disassembler aims to prevent:  incorrect instruction encoding, incorrect disassembly formatting, and misinterpretation of instruction semantics. Examples could be given related to these.

8. **Summarize the functionality:** Combine the observations to provide a concise summary of the file's purpose.

9. **Address the "Part X of 8" instruction:** Acknowledge that this is part 2 and focus the summary on the content of this specific part. Avoid making assumptions about the other parts.

**(Self-Correction/Refinement during thought process):**

* Initially, I might have thought about directly linking JavaScript code to the disassembler output. However, realizing this is a *unit test* for the disassembler itself clarifies that the focus is on low-level ARM64 instructions, not the higher-level JavaScript compilation process.
* When considering JavaScript examples, I initially thought of complex code. A simpler example illustrating a basic operation that gets compiled is more effective for demonstrating the *potential* role of the disassembler.
*  For common errors, I initially focused on assembly language errors. Reframing it to the *purpose* of testing the disassembler—ensuring correct interpretation of machine code—makes the examples more relevant.
这是 V8 源代码文件 `v8/test/unittests/assembler/disasm-arm64-unittest.cc` 的第二部分，该文件主要用于测试 V8 引擎中 ARM64 架构的反汇编器 (`disassembler`) 的功能。

**功能归纳 (基于提供的代码片段):**

这部分代码主要通过一系列单元测试来验证 ARM64 反汇编器是否能正确地将不同的 ARM64 指令反汇编成可读的汇编代码字符串。 它涵盖了以下指令类型：

* **数据处理指令 (Data Processing Instructions):**
    *  `and`, `orr`, `eor`, `bic` 等逻辑运算指令，包括带立即数和寄存器移位的操作数。
    *  `ands`, `bics`, `tst` 等设置标志位的逻辑运算指令。
    *  `mvn` (move negative) 指令。
    *  `mov` (move) 指令，通过 `orr` 和零寄存器实现。
    *  `lslv`, `lsrv`, `asrv`, `rorv` 等基于寄存器移位的指令。
* **地址生成指令 (Address Generation Instruction):**
    *  `adr` 指令，测试了正负偏移量以及不同的偏移量大小。
* **分支指令 (Branch Instructions):**
    *  无条件分支 `b` 和带链接分支 `bl`，测试了正负偏移量和不同偏移量大小。
    *  条件分支 `b.eq`, `b.mi` 等，测试了不同的条件码。
    *  条件零跳转 `cbz` 和条件非零跳转 `cbnz`。
    *  测试位跳转 `tbz` 和测试位非零跳转 `tbnz`，测试了不同的位索引和偏移量。
    *  寄存器分支 `br`, `blr` 和返回指令 `ret`。
* **加载/存储指令 (Load/Store Instructions):**
    *  基本的字 (word) 和双字 (doubleword) 加载/存储指令 `ldr` 和 `str`，测试了立即数偏移 (包括正负偏移量和不同大小的偏移量)。
    *  带前/后索引的加载/存储指令 `ldr ... !` 和 `ldr ..., #offset`，测试了不同的偏移量。
    *  带寄存器偏移的加载/存储指令，测试了不同的扩展方式 (`UXTW`, `SXTW`, `SXTX`) 和移位量。
    *  加载并符号扩展的字 `ldrsw` 指令。
    *  字节 (byte) 加载/存储指令 `ldrb` 和 `strb`。
    *  半字 (half-word) 加载/存储指令 `ldrh` 和 `strh`。
    *  向量寄存器的加载/存储指令 (`ldr s0`, `ldr d6`, `ldr b0`, `ldr h6`, `ldr q12`, `str s12`, 等等)，测试了不同的偏移量和前/后索引方式。
    *  非对齐的加载/存储指令 (`ldur`, `stur`, `ldurb`, `ldursb`, `ldurh`, `ldursh`, `ldursw`)，测试了不同的偏移量。
    *  加载/存储一对寄存器指令 `ldp`，测试了不同的偏移量和前/后索引方式。

**关于文件类型和 JavaScript 关系:**

* `v8/test/unittests/assembler/disasm-arm64-unittest.cc` 以 `.cc` 结尾，因此它是一个 **C++ 源代码文件**，而不是 V8 Torque 源代码。
* 该文件直接测试反汇编器的功能，反汇编器是将机器码转换为汇编代码的工具。  虽然 JavaScript 代码最终会被编译成机器码，但这个单元测试 **不直接涉及 JavaScript 代码的执行或编译过程**。 它的目的是确保反汇编器能够正确解析生成的 ARM64 指令。

**代码逻辑推理示例:**

假设输入以下汇编指令（通过 `Assembler` 生成）：

```c++
__ mov(w0, w1);
```

这段代码使用了 `Assembler` 的 `mov` 函数，将寄存器 `w1` 的值移动到寄存器 `w0`。

**预期输出（通过反汇编器）:**

```
"mov w0, w1"
```

`COMPARE(orr(w0, wzr, Operand(w1)), "mov w0, w1");`  这行代码实际上是通过 `orr` 指令和零寄存器 `wzr` 来模拟 `mov` 指令的。  因此，反汇编器应该将其正确地反汇编为 `mov w0, w1`。

**用户常见的编程错误（与反汇编器测试相关的间接联系）:**

虽然这个文件是测试代码，但它测试的功能与理解机器码密切相关。 用户在编写底层代码或进行性能分析时，可能会遇到以下与反汇编相关的错误：

1. **误解指令的含义:**  用户可能不完全理解某个 ARM64 指令的功能和副作用，导致分析反汇编输出时产生错误的结论。
   * **例子:** 错误地认为 `ands` 指令只会进行逻辑与运算，而忽略了它还会设置 CPU 的标志位。

2. **忽略指令的寻址模式:** ARM64 提供了多种寻址模式。 用户可能不理解特定寻址模式的计算方式，从而无法正确解释反汇编输出中内存地址的含义。
   * **例子:**  看到 `ldr w0, [x1, #4]`，错误地认为是从 `x1` 寄存器指向的地址读取，而忽略了 `#4` 表示偏移量。

3. **对立即数的理解错误:** ARM64 指令中的立即数可能需要特定的编码方式。 用户可能无法正确地将反汇编输出中的立即数转换回原始数值。
   * **例子:**  对于某些移位操作，立即数的含义可能不是直接的移位量，而是经过编码的值。

**总结:**

这部分 `disasm-arm64-unittest.cc` 文件的主要功能是 **系统地测试 V8 引擎中 ARM64 反汇编器的正确性**。 它通过生成各种 ARM64 指令，然后断言反汇编器能够将其转换回预期格式的汇编代码字符串来实现这一点。 这对于确保 V8 在 ARM64 架构上的正确运行和调试至关重要。

Prompt: 
```
这是目录为v8/test/unittests/assembler/disasm-arm64-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/assembler/disasm-arm64-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共8部分，请归纳一下它的功能

"""
 #23");
  COMPARE(eon(w27, w28, Operand(w29, ROR, 24)), "eon w27, w28, w29, ror #24");

  COMPARE(ands(w0, w1, Operand(w2)), "ands w0, w1, w2");
  COMPARE(ands(x3, x4, Operand(x5, LSL, 1)), "ands x3, x4, x5, lsl #1");
  COMPARE(ands(w6, w7, Operand(w8, LSR, 2)), "ands w6, w7, w8, lsr #2");
  COMPARE(ands(x9, x10, Operand(x11, ASR, 3)), "ands x9, x10, x11, asr #3");
  COMPARE(ands(w12, w13, Operand(w14, ROR, 4)), "ands w12, w13, w14, ror #4");

  COMPARE(bics(w15, w16, Operand(w17)), "bics w15, w16, w17");
  COMPARE(bics(x18, x19, Operand(x20, LSL, 5)), "bics x18, x19, x20, lsl #5");
  COMPARE(bics(w21, w22, Operand(w23, LSR, 6)), "bics w21, w22, w23, lsr #6");
  COMPARE(bics(x24, x25, Operand(x26, ASR, 7)), "bics x24, x25, x26, asr #7");
  COMPARE(bics(w27, w28, Operand(w29, ROR, 8)), "bics w27, w28, w29, ror #8");

  COMPARE(tst(w0, Operand(w1)), "tst w0, w1");
  COMPARE(tst(w2, Operand(w3, ROR, 10)), "tst w2, w3, ror #10");
  COMPARE(tst(x0, Operand(x1)), "tst x0, x1");
  COMPARE(tst(x2, Operand(x3, ROR, 42)), "tst x2, x3, ror #42");

  COMPARE(orn(w0, wzr, Operand(w1)), "mvn w0, w1");
  COMPARE(orn(w2, wzr, Operand(w3, ASR, 5)), "mvn w2, w3, asr #5");
  COMPARE(orn(x0, xzr, Operand(x1)), "mvn x0, x1");
  COMPARE(orn(x2, xzr, Operand(x3, ASR, 42)), "mvn x2, x3, asr #42");

  COMPARE(orr(w0, wzr, Operand(w1)), "mov w0, w1");
  COMPARE(orr(x0, xzr, Operand(x1)), "mov x0, x1");
  COMPARE(orr(w16, wzr, Operand(w17, LSL, 1)), "orr w16, wzr, w17, lsl #1");
  COMPARE(orr(x16, xzr, Operand(x17, ASR, 2)), "orr x16, xzr, x17, asr #2");

  CLEANUP();
}

TEST_F(DisasmArm64Test, dp_2_source) {
  SET_UP_ASM();

  COMPARE(lslv(w0, w1, w2), "lsl w0, w1, w2");
  COMPARE(lslv(x3, x4, x5), "lsl x3, x4, x5");
  COMPARE(lsrv(w6, w7, w8), "lsr w6, w7, w8");
  COMPARE(lsrv(x9, x10, x11), "lsr x9, x10, x11");
  COMPARE(asrv(w12, w13, w14), "asr w12, w13, w14");
  COMPARE(asrv(x15, x16, x17), "asr x15, x16, x17");
  COMPARE(rorv(w18, w19, w20), "ror w18, w19, w20");
  COMPARE(rorv(x21, x22, x23), "ror x21, x22, x23");

  CLEANUP();
}

TEST_F(DisasmArm64Test, adr) {
  SET_UP_ASM();

  char expected[100];
  snprintf(expected, sizeof(expected), "adr x0, #+0x0 (addr %p)", buf);
  COMPARE(adr(x0, 0), expected);
  snprintf(expected, sizeof(expected), "adr x0, #+0x1 (addr %p)", buf + 1);
  COMPARE(adr(x0, 1), expected);
  snprintf(expected, sizeof(expected), "adr x0, #-0x1 (addr %p)", buf - 1);
  COMPARE(adr(x0, -1), expected);
  COMPARE_PREFIX(adr(x0, 0), "adr x0, #+0x0");
  COMPARE_PREFIX(adr(x1, 1), "adr x1, #+0x1");
  COMPARE_PREFIX(adr(x2, -1), "adr x2, #-0x1");
  COMPARE_PREFIX(adr(x3, 4), "adr x3, #+0x4");
  COMPARE_PREFIX(adr(x4, -4), "adr x4, #-0x4");
  COMPARE_PREFIX(adr(x5, 0x000fffff), "adr x5, #+0xfffff");
  COMPARE_PREFIX(adr(x6, -0x00100000), "adr x6, #-0x100000");
  COMPARE_PREFIX(adr(xzr, 0), "adr xzr, #+0x0");

  CLEANUP();
}

TEST_F(DisasmArm64Test, branch) {
  SET_UP_ASM();

#define INST_OFF(x) ((x) >> kInstrSizeLog2)
  COMPARE_PREFIX(b(INST_OFF(0x4)), "b #+0x4");
  COMPARE_PREFIX(b(INST_OFF(-0x4)), "b #-0x4");
  COMPARE_PREFIX(b(INST_OFF(0x7fffffc)), "b #+0x7fffffc");
  COMPARE_PREFIX(b(INST_OFF(-0x8000000)), "b #-0x8000000");
  COMPARE_PREFIX(b(INST_OFF(0xffffc), eq), "b.eq #+0xffffc");
  COMPARE_PREFIX(b(INST_OFF(-0x100000), mi), "b.mi #-0x100000");
  COMPARE_PREFIX(bl(INST_OFF(0x4)), "bl #+0x4");
  COMPARE_PREFIX(bl(INST_OFF(-0x4)), "bl #-0x4");
  COMPARE_PREFIX(bl(INST_OFF(0xffffc)), "bl #+0xffffc");
  COMPARE_PREFIX(bl(INST_OFF(-0x100000)), "bl #-0x100000");
  COMPARE_PREFIX(cbz(w0, INST_OFF(0xffffc)), "cbz w0, #+0xffffc");
  COMPARE_PREFIX(cbz(x1, INST_OFF(-0x100000)), "cbz x1, #-0x100000");
  COMPARE_PREFIX(cbnz(w2, INST_OFF(0xffffc)), "cbnz w2, #+0xffffc");
  COMPARE_PREFIX(cbnz(x3, INST_OFF(-0x100000)), "cbnz x3, #-0x100000");
  COMPARE_PREFIX(tbz(w4, 0, INST_OFF(0x7ffc)), "tbz w4, #0, #+0x7ffc");
  COMPARE_PREFIX(tbz(x5, 63, INST_OFF(-0x8000)), "tbz x5, #63, #-0x8000");
  COMPARE_PREFIX(tbz(w6, 31, INST_OFF(0)), "tbz w6, #31, #+0x0");
  COMPARE_PREFIX(tbz(x7, 31, INST_OFF(0x4)), "tbz w7, #31, #+0x4");
  COMPARE_PREFIX(tbz(x8, 32, INST_OFF(0x8)), "tbz x8, #32, #+0x8");
  COMPARE_PREFIX(tbnz(w8, 0, INST_OFF(0x7ffc)), "tbnz w8, #0, #+0x7ffc");
  COMPARE_PREFIX(tbnz(x9, 63, INST_OFF(-0x8000)), "tbnz x9, #63, #-0x8000");
  COMPARE_PREFIX(tbnz(w10, 31, INST_OFF(0)), "tbnz w10, #31, #+0x0");
  COMPARE_PREFIX(tbnz(x11, 31, INST_OFF(0x4)), "tbnz w11, #31, #+0x4");
  COMPARE_PREFIX(tbnz(x12, 32, INST_OFF(0x8)), "tbnz x12, #32, #+0x8");
#undef INST_OFF
  COMPARE(br(x0), "br x0");
  COMPARE(blr(x1), "blr x1");
  COMPARE(ret(x2), "ret x2");
  COMPARE(ret(lr), "ret");

  CLEANUP();
}

TEST_F(DisasmArm64Test, load_store) {
  SET_UP_ASM();

  COMPARE(ldr(w0, MemOperand(x1)), "ldr w0, [x1]");
  COMPARE(ldr(w2, MemOperand(x3, 4)), "ldr w2, [x3, #4]");
  COMPARE(ldr(w4, MemOperand(x5, 16380)), "ldr w4, [x5, #16380]");
  COMPARE(ldr(x6, MemOperand(x7)), "ldr x6, [x7]");
  COMPARE(ldr(x8, MemOperand(x9, 8)), "ldr x8, [x9, #8]");
  COMPARE(ldr(x10, MemOperand(x11, 32760)), "ldr x10, [x11, #32760]");
  COMPARE(str(w12, MemOperand(x13)), "str w12, [x13]");
  COMPARE(str(w14, MemOperand(x15, 4)), "str w14, [x15, #4]");
  COMPARE(str(w16, MemOperand(x17, 16380)), "str w16, [x17, #16380]");
  COMPARE(str(x18, MemOperand(x19)), "str x18, [x19]");
  COMPARE(str(x20, MemOperand(x21, 8)), "str x20, [x21, #8]");
  COMPARE(str(x22, MemOperand(x23, 32760)), "str x22, [x23, #32760]");

  COMPARE(ldr(w0, MemOperand(x1, 4, PreIndex)), "ldr w0, [x1, #4]!");
  COMPARE(ldr(w2, MemOperand(x3, 255, PreIndex)), "ldr w2, [x3, #255]!");
  COMPARE(ldr(w4, MemOperand(x5, -256, PreIndex)), "ldr w4, [x5, #-256]!");
  COMPARE(ldr(x6, MemOperand(x7, 8, PreIndex)), "ldr x6, [x7, #8]!");
  COMPARE(ldr(x8, MemOperand(x9, 255, PreIndex)), "ldr x8, [x9, #255]!");
  COMPARE(ldr(x10, MemOperand(x11, -256, PreIndex)), "ldr x10, [x11, #-256]!");
  COMPARE(str(w12, MemOperand(x13, 4, PreIndex)), "str w12, [x13, #4]!");
  COMPARE(str(w14, MemOperand(x15, 255, PreIndex)), "str w14, [x15, #255]!");
  COMPARE(str(w16, MemOperand(x17, -256, PreIndex)), "str w16, [x17, #-256]!");
  COMPARE(str(x18, MemOperand(x19, 8, PreIndex)), "str x18, [x19, #8]!");
  COMPARE(str(x20, MemOperand(x21, 255, PreIndex)), "str x20, [x21, #255]!");
  COMPARE(str(x22, MemOperand(x23, -256, PreIndex)), "str x22, [x23, #-256]!");

  COMPARE(ldr(w0, MemOperand(x1, 4, PostIndex)), "ldr w0, [x1], #4");
  COMPARE(ldr(w2, MemOperand(x3, 255, PostIndex)), "ldr w2, [x3], #255");
  COMPARE(ldr(w4, MemOperand(x5, -256, PostIndex)), "ldr w4, [x5], #-256");
  COMPARE(ldr(x6, MemOperand(x7, 8, PostIndex)), "ldr x6, [x7], #8");
  COMPARE(ldr(x8, MemOperand(x9, 255, PostIndex)), "ldr x8, [x9], #255");
  COMPARE(ldr(x10, MemOperand(x11, -256, PostIndex)), "ldr x10, [x11], #-256");
  COMPARE(str(w12, MemOperand(x13, 4, PostIndex)), "str w12, [x13], #4");
  COMPARE(str(w14, MemOperand(x15, 255, PostIndex)), "str w14, [x15], #255");
  COMPARE(str(w16, MemOperand(x17, -256, PostIndex)), "str w16, [x17], #-256");
  COMPARE(str(x18, MemOperand(x19, 8, PostIndex)), "str x18, [x19], #8");
  COMPARE(str(x20, MemOperand(x21, 255, PostIndex)), "str x20, [x21], #255");
  COMPARE(str(x22, MemOperand(x23, -256, PostIndex)), "str x22, [x23], #-256");

  COMPARE(ldr(w24, MemOperand(x28)), "ldr w24, [x28]");
  COMPARE(ldr(x25, MemOperand(x28, 8)), "ldr x25, [x28, #8]");
  COMPARE(str(w26, MemOperand(x28, 4, PreIndex)), "str w26, [x28, #4]!");
  COMPARE(str(cp, MemOperand(x28, -8, PostIndex)), "str cp, [x28], #-8");

  COMPARE(ldrsw(x0, MemOperand(x1)), "ldrsw x0, [x1]");
  COMPARE(ldrsw(x2, MemOperand(x3, 8)), "ldrsw x2, [x3, #8]");
  COMPARE(ldrsw(x4, MemOperand(x5, 42, PreIndex)), "ldrsw x4, [x5, #42]!");
  COMPARE(ldrsw(x6, MemOperand(x7, -11, PostIndex)), "ldrsw x6, [x7], #-11");

  CLEANUP();
}

TEST_F(DisasmArm64Test, load_store_regoffset) {
  SET_UP_ASM();

  COMPARE(ldr(w0, MemOperand(x1, w2, UXTW)), "ldr w0, [x1, w2, uxtw]");
  COMPARE(ldr(w3, MemOperand(x4, w5, UXTW, 2)), "ldr w3, [x4, w5, uxtw #2]");
  COMPARE(ldr(w6, MemOperand(x7, x8)), "ldr w6, [x7, x8]");
  COMPARE(ldr(w9, MemOperand(x10, x11, LSL, 2)), "ldr w9, [x10, x11, lsl #2]");
  COMPARE(ldr(w12, MemOperand(x13, w14, SXTW)), "ldr w12, [x13, w14, sxtw]");
  COMPARE(ldr(w15, MemOperand(x16, w17, SXTW, 2)),
          "ldr w15, [x16, w17, sxtw #2]");
  COMPARE(ldr(w18, MemOperand(x19, x20, SXTX)), "ldr w18, [x19, x20, sxtx]");
  COMPARE(ldr(w21, MemOperand(x22, x23, SXTX, 2)),
          "ldr w21, [x22, x23, sxtx #2]");
  COMPARE(ldr(x0, MemOperand(x1, w2, UXTW)), "ldr x0, [x1, w2, uxtw]");
  COMPARE(ldr(x3, MemOperand(x4, w5, UXTW, 3)), "ldr x3, [x4, w5, uxtw #3]");
  COMPARE(ldr(x6, MemOperand(x7, x8)), "ldr x6, [x7, x8]");
  COMPARE(ldr(x9, MemOperand(x10, x11, LSL, 3)), "ldr x9, [x10, x11, lsl #3]");
  COMPARE(ldr(x12, MemOperand(x13, w14, SXTW)), "ldr x12, [x13, w14, sxtw]");
  COMPARE(ldr(x15, MemOperand(x16, w17, SXTW, 3)),
          "ldr x15, [x16, w17, sxtw #3]");
  COMPARE(ldr(x18, MemOperand(x19, x20, SXTX)), "ldr x18, [x19, x20, sxtx]");
  COMPARE(ldr(x21, MemOperand(x22, x23, SXTX, 3)),
          "ldr x21, [x22, x23, sxtx #3]");

  COMPARE(str(w0, MemOperand(x1, w2, UXTW)), "str w0, [x1, w2, uxtw]");
  COMPARE(str(w3, MemOperand(x4, w5, UXTW, 2)), "str w3, [x4, w5, uxtw #2]");
  COMPARE(str(w6, MemOperand(x7, x8)), "str w6, [x7, x8]");
  COMPARE(str(w9, MemOperand(x10, x11, LSL, 2)), "str w9, [x10, x11, lsl #2]");
  COMPARE(str(w12, MemOperand(x13, w14, SXTW)), "str w12, [x13, w14, sxtw]");
  COMPARE(str(w15, MemOperand(x16, w17, SXTW, 2)),
          "str w15, [x16, w17, sxtw #2]");
  COMPARE(str(w18, MemOperand(x19, x20, SXTX)), "str w18, [x19, x20, sxtx]");
  COMPARE(str(w21, MemOperand(x22, x23, SXTX, 2)),
          "str w21, [x22, x23, sxtx #2]");
  COMPARE(str(x0, MemOperand(x1, w2, UXTW)), "str x0, [x1, w2, uxtw]");
  COMPARE(str(x3, MemOperand(x4, w5, UXTW, 3)), "str x3, [x4, w5, uxtw #3]");
  COMPARE(str(x6, MemOperand(x7, x8)), "str x6, [x7, x8]");
  COMPARE(str(x9, MemOperand(x10, x11, LSL, 3)), "str x9, [x10, x11, lsl #3]");
  COMPARE(str(x12, MemOperand(x13, w14, SXTW)), "str x12, [x13, w14, sxtw]");
  COMPARE(str(x15, MemOperand(x16, w17, SXTW, 3)),
          "str x15, [x16, w17, sxtw #3]");
  COMPARE(str(x18, MemOperand(x19, x20, SXTX)), "str x18, [x19, x20, sxtx]");
  COMPARE(str(x21, MemOperand(x22, x23, SXTX, 3)),
          "str x21, [x22, x23, sxtx #3]");

  COMPARE(ldrb(w0, MemOperand(x1, w2, UXTW)), "ldrb w0, [x1, w2, uxtw]");
  COMPARE(ldrb(w6, MemOperand(x7, x8)), "ldrb w6, [x7, x8]");
  COMPARE(ldrb(w12, MemOperand(x13, w14, SXTW)), "ldrb w12, [x13, w14, sxtw]");
  COMPARE(ldrb(w18, MemOperand(x19, x20, SXTX)), "ldrb w18, [x19, x20, sxtx]");
  COMPARE(strb(w0, MemOperand(x1, w2, UXTW)), "strb w0, [x1, w2, uxtw]");
  COMPARE(strb(w6, MemOperand(x7, x8)), "strb w6, [x7, x8]");
  COMPARE(strb(w12, MemOperand(x13, w14, SXTW)), "strb w12, [x13, w14, sxtw]");
  COMPARE(strb(w18, MemOperand(x19, x20, SXTX)), "strb w18, [x19, x20, sxtx]");

  COMPARE(ldrh(w0, MemOperand(x1, w2, UXTW)), "ldrh w0, [x1, w2, uxtw]");
  COMPARE(ldrh(w3, MemOperand(x4, w5, UXTW, 1)), "ldrh w3, [x4, w5, uxtw #1]");
  COMPARE(ldrh(w6, MemOperand(x7, x8)), "ldrh w6, [x7, x8]");
  COMPARE(ldrh(w9, MemOperand(x10, x11, LSL, 1)),
          "ldrh w9, [x10, x11, lsl #1]");
  COMPARE(ldrh(w12, MemOperand(x13, w14, SXTW)), "ldrh w12, [x13, w14, sxtw]");
  COMPARE(ldrh(w15, MemOperand(x16, w17, SXTW, 1)),
          "ldrh w15, [x16, w17, sxtw #1]");
  COMPARE(ldrh(w18, MemOperand(x19, x20, SXTX)), "ldrh w18, [x19, x20, sxtx]");
  COMPARE(ldrh(w21, MemOperand(x22, x23, SXTX, 1)),
          "ldrh w21, [x22, x23, sxtx #1]");
  COMPARE(strh(w0, MemOperand(x1, w2, UXTW)), "strh w0, [x1, w2, uxtw]");
  COMPARE(strh(w3, MemOperand(x4, w5, UXTW, 1)), "strh w3, [x4, w5, uxtw #1]");
  COMPARE(strh(w6, MemOperand(x7, x8)), "strh w6, [x7, x8]");
  COMPARE(strh(w9, MemOperand(x10, x11, LSL, 1)),
          "strh w9, [x10, x11, lsl #1]");
  COMPARE(strh(w12, MemOperand(x13, w14, SXTW)), "strh w12, [x13, w14, sxtw]");
  COMPARE(strh(w15, MemOperand(x16, w17, SXTW, 1)),
          "strh w15, [x16, w17, sxtw #1]");
  COMPARE(strh(w18, MemOperand(x19, x20, SXTX)), "strh w18, [x19, x20, sxtx]");
  COMPARE(strh(w21, MemOperand(x22, x23, SXTX, 1)),
          "strh w21, [x22, x23, sxtx #1]");

  COMPARE(ldr(x0, MemOperand(x28, wzr, SXTW)), "ldr x0, [x28, wzr, sxtw]");
  COMPARE(str(x1, MemOperand(x28, xzr)), "str x1, [x28, xzr]");

  CLEANUP();
}

TEST_F(DisasmArm64Test, load_store_byte) {
  SET_UP_ASM();

  COMPARE(ldrb(w0, MemOperand(x1)), "ldrb w0, [x1]");
  COMPARE(ldrb(x2, MemOperand(x3)), "ldrb w2, [x3]");
  COMPARE(ldrb(w4, MemOperand(x5, 4095)), "ldrb w4, [x5, #4095]");
  COMPARE(ldrb(w6, MemOperand(x7, 255, PreIndex)), "ldrb w6, [x7, #255]!");
  COMPARE(ldrb(w8, MemOperand(x9, -256, PreIndex)), "ldrb w8, [x9, #-256]!");
  COMPARE(ldrb(w10, MemOperand(x11, 255, PostIndex)), "ldrb w10, [x11], #255");
  COMPARE(ldrb(w12, MemOperand(x13, -256, PostIndex)),
          "ldrb w12, [x13], #-256");
  COMPARE(strb(w14, MemOperand(x15)), "strb w14, [x15]");
  COMPARE(strb(x16, MemOperand(x17)), "strb w16, [x17]");
  COMPARE(strb(w18, MemOperand(x19, 4095)), "strb w18, [x19, #4095]");
  COMPARE(strb(w20, MemOperand(x21, 255, PreIndex)), "strb w20, [x21, #255]!");
  COMPARE(strb(w22, MemOperand(x23, -256, PreIndex)),
          "strb w22, [x23, #-256]!");
  COMPARE(strb(w24, MemOperand(x25, 255, PostIndex)), "strb w24, [x25], #255");
  COMPARE(strb(w26, MemOperand(cp, -256, PostIndex)), "strb w26, [cp], #-256");
  COMPARE(ldrb(w28, MemOperand(x28, 3, PostIndex)), "ldrb w28, [x28], #3");
  COMPARE(strb(fp, MemOperand(x28, -42, PreIndex)), "strb w29, [x28, #-42]!");
  COMPARE(ldrsb(w0, MemOperand(x1)), "ldrsb w0, [x1]");
  COMPARE(ldrsb(x2, MemOperand(x3, 8)), "ldrsb x2, [x3, #8]");
  COMPARE(ldrsb(w4, MemOperand(x5, 42, PreIndex)), "ldrsb w4, [x5, #42]!");
  COMPARE(ldrsb(x6, MemOperand(x7, -11, PostIndex)), "ldrsb x6, [x7], #-11");

  CLEANUP();
}

TEST_F(DisasmArm64Test, load_store_half) {
  SET_UP_ASM();

  COMPARE(ldrh(w0, MemOperand(x1)), "ldrh w0, [x1]");
  COMPARE(ldrh(x2, MemOperand(x3)), "ldrh w2, [x3]");
  COMPARE(ldrh(w4, MemOperand(x5, 8190)), "ldrh w4, [x5, #8190]");
  COMPARE(ldrh(w6, MemOperand(x7, 255, PreIndex)), "ldrh w6, [x7, #255]!");
  COMPARE(ldrh(w8, MemOperand(x9, -256, PreIndex)), "ldrh w8, [x9, #-256]!");
  COMPARE(ldrh(w10, MemOperand(x11, 255, PostIndex)), "ldrh w10, [x11], #255");
  COMPARE(ldrh(w12, MemOperand(x13, -256, PostIndex)),
          "ldrh w12, [x13], #-256");
  COMPARE(strh(w14, MemOperand(x15)), "strh w14, [x15]");
  COMPARE(strh(x16, MemOperand(x17)), "strh w16, [x17]");
  COMPARE(strh(w18, MemOperand(x19, 8190)), "strh w18, [x19, #8190]");
  COMPARE(strh(w20, MemOperand(x21, 255, PreIndex)), "strh w20, [x21, #255]!");
  COMPARE(strh(w22, MemOperand(x23, -256, PreIndex)),
          "strh w22, [x23, #-256]!");
  COMPARE(strh(w24, MemOperand(x25, 255, PostIndex)), "strh w24, [x25], #255");
  COMPARE(strh(w26, MemOperand(cp, -256, PostIndex)), "strh w26, [cp], #-256");
  COMPARE(ldrh(w28, MemOperand(x28, 3, PostIndex)), "ldrh w28, [x28], #3");
  COMPARE(strh(fp, MemOperand(x28, -42, PreIndex)), "strh w29, [x28, #-42]!");
  COMPARE(ldrh(w30, MemOperand(x0, 255)), "ldurh w30, [x0, #255]");
  COMPARE(ldrh(x1, MemOperand(x2, -256)), "ldurh w1, [x2, #-256]");
  COMPARE(strh(w3, MemOperand(x4, 255)), "sturh w3, [x4, #255]");
  COMPARE(strh(x5, MemOperand(x6, -256)), "sturh w5, [x6, #-256]");
  COMPARE(ldrsh(w0, MemOperand(x1)), "ldrsh w0, [x1]");
  COMPARE(ldrsh(w2, MemOperand(x3, 8)), "ldrsh w2, [x3, #8]");
  COMPARE(ldrsh(w4, MemOperand(x5, 42, PreIndex)), "ldrsh w4, [x5, #42]!");
  COMPARE(ldrsh(x6, MemOperand(x7, -11, PostIndex)), "ldrsh x6, [x7], #-11");

  CLEANUP();
}

TEST_F(DisasmArm64Test, load_store_v_offset) {
  SET_UP_ASM();

  COMPARE(ldr(s0, MemOperand(x1)), "ldr s0, [x1]");
  COMPARE(ldr(s2, MemOperand(x3, 4)), "ldr s2, [x3, #4]");
  COMPARE(ldr(s4, MemOperand(x5, 16380)), "ldr s4, [x5, #16380]");
  COMPARE(ldr(d6, MemOperand(x7)), "ldr d6, [x7]");
  COMPARE(ldr(d8, MemOperand(x9, 8)), "ldr d8, [x9, #8]");
  COMPARE(ldr(d10, MemOperand(x11, 32760)), "ldr d10, [x11, #32760]");
  COMPARE(str(s12, MemOperand(x13)), "str s12, [x13]");
  COMPARE(str(s14, MemOperand(x15, 4)), "str s14, [x15, #4]");
  COMPARE(str(s16, MemOperand(x17, 16380)), "str s16, [x17, #16380]");
  COMPARE(str(d18, MemOperand(x19)), "str d18, [x19]");
  COMPARE(str(d20, MemOperand(x21, 8)), "str d20, [x21, #8]");
  COMPARE(str(d22, MemOperand(x23, 32760)), "str d22, [x23, #32760]");

  COMPARE(ldr(b0, MemOperand(x1)), "ldr b0, [x1]");
  COMPARE(ldr(b2, MemOperand(x3, 1)), "ldr b2, [x3, #1]");
  COMPARE(ldr(b4, MemOperand(x5, 4095)), "ldr b4, [x5, #4095]");
  COMPARE(ldr(h6, MemOperand(x7)), "ldr h6, [x7]");
  COMPARE(ldr(h8, MemOperand(x9, 2)), "ldr h8, [x9, #2]");
  COMPARE(ldr(h10, MemOperand(x11, 8190)), "ldr h10, [x11, #8190]");
  COMPARE(ldr(q12, MemOperand(x13)), "ldr q12, [x13]");
  COMPARE(ldr(q14, MemOperand(x15, 16)), "ldr q14, [x15, #16]");
  COMPARE(ldr(q16, MemOperand(x17, 65520)), "ldr q16, [x17, #65520]");
  COMPARE(str(b18, MemOperand(x19)), "str b18, [x19]");
  COMPARE(str(b20, MemOperand(x21, 1)), "str b20, [x21, #1]");
  COMPARE(str(b22, MemOperand(x23, 4095)), "str b22, [x23, #4095]");
  COMPARE(str(h24, MemOperand(x25)), "str h24, [x25]");
  COMPARE(str(h26, MemOperand(x27, 2)), "str h26, [cp, #2]");
  COMPARE(str(h28, MemOperand(x29, 8190)), "str h28, [fp, #8190]");
  COMPARE(str(q30, MemOperand(x30)), "str q30, [lr]");
  COMPARE(str(q31, MemOperand(x1, 16)), "str q31, [x1, #16]");
  COMPARE(str(q0, MemOperand(x3, 65520)), "str q0, [x3, #65520]");

  COMPARE(ldr(s24, MemOperand(sp)), "ldr s24, [sp]");
  COMPARE(ldr(d25, MemOperand(sp, 8)), "ldr d25, [sp, #8]");
  COMPARE(ldr(b26, MemOperand(sp, 1)), "ldr b26, [sp, #1]");
  COMPARE(ldr(h27, MemOperand(sp, 2)), "ldr h27, [sp, #2]");
  COMPARE(ldr(q28, MemOperand(sp, 16)), "ldr q28, [sp, #16]");

  CLEANUP();
}

TEST_F(DisasmArm64Test, load_store_v_pre) {
  SET_UP_ASM();

  COMPARE(ldr(s0, MemOperand(x1, 4, PreIndex)), "ldr s0, [x1, #4]!");
  COMPARE(ldr(s2, MemOperand(x3, 255, PreIndex)), "ldr s2, [x3, #255]!");
  COMPARE(ldr(s4, MemOperand(x5, -256, PreIndex)), "ldr s4, [x5, #-256]!");
  COMPARE(ldr(d6, MemOperand(x7, 8, PreIndex)), "ldr d6, [x7, #8]!");
  COMPARE(ldr(d8, MemOperand(x9, 255, PreIndex)), "ldr d8, [x9, #255]!");
  COMPARE(ldr(d10, MemOperand(x11, -256, PreIndex)), "ldr d10, [x11, #-256]!");

  COMPARE(str(s12, MemOperand(x13, 4, PreIndex)), "str s12, [x13, #4]!");
  COMPARE(str(s14, MemOperand(x15, 255, PreIndex)), "str s14, [x15, #255]!");
  COMPARE(str(s16, MemOperand(x17, -256, PreIndex)), "str s16, [x17, #-256]!");
  COMPARE(str(d18, MemOperand(x19, 8, PreIndex)), "str d18, [x19, #8]!");
  COMPARE(str(d20, MemOperand(x21, 255, PreIndex)), "str d20, [x21, #255]!");
  COMPARE(str(d22, MemOperand(x23, -256, PreIndex)), "str d22, [x23, #-256]!");

  COMPARE(ldr(b0, MemOperand(x1, 1, PreIndex)), "ldr b0, [x1, #1]!");
  COMPARE(ldr(b2, MemOperand(x3, 255, PreIndex)), "ldr b2, [x3, #255]!");
  COMPARE(ldr(b4, MemOperand(x5, -256, PreIndex)), "ldr b4, [x5, #-256]!");
  COMPARE(ldr(h6, MemOperand(x7, 2, PreIndex)), "ldr h6, [x7, #2]!");
  COMPARE(ldr(h8, MemOperand(x9, 255, PreIndex)), "ldr h8, [x9, #255]!");
  COMPARE(ldr(h10, MemOperand(x11, -256, PreIndex)), "ldr h10, [x11, #-256]!");
  COMPARE(ldr(q12, MemOperand(x13, 16, PreIndex)), "ldr q12, [x13, #16]!");
  COMPARE(ldr(q14, MemOperand(x15, 255, PreIndex)), "ldr q14, [x15, #255]!");
  COMPARE(ldr(q16, MemOperand(x17, -256, PreIndex)), "ldr q16, [x17, #-256]!");

  COMPARE(str(b18, MemOperand(x19, 1, PreIndex)), "str b18, [x19, #1]!");
  COMPARE(str(b20, MemOperand(x21, 255, PreIndex)), "str b20, [x21, #255]!");
  COMPARE(str(b22, MemOperand(x23, -256, PreIndex)), "str b22, [x23, #-256]!");
  COMPARE(str(h24, MemOperand(x25, 2, PreIndex)), "str h24, [x25, #2]!");
  COMPARE(str(h26, MemOperand(x27, 255, PreIndex)), "str h26, [cp, #255]!");
  COMPARE(str(h28, MemOperand(x29, -256, PreIndex)), "str h28, [fp, #-256]!");
  COMPARE(str(q30, MemOperand(x1, 16, PreIndex)), "str q30, [x1, #16]!");
  COMPARE(str(q31, MemOperand(x3, 255, PreIndex)), "str q31, [x3, #255]!");
  COMPARE(str(q0, MemOperand(x5, -256, PreIndex)), "str q0, [x5, #-256]!");

  COMPARE(str(b24, MemOperand(sp, 1, PreIndex)), "str b24, [sp, #1]!");
  COMPARE(str(h25, MemOperand(sp, -2, PreIndex)), "str h25, [sp, #-2]!");
  COMPARE(str(s26, MemOperand(sp, 4, PreIndex)), "str s26, [sp, #4]!");
  COMPARE(str(d27, MemOperand(sp, -8, PreIndex)), "str d27, [sp, #-8]!");
  COMPARE(str(q28, MemOperand(sp, 16, PreIndex)), "str q28, [sp, #16]!");

  CLEANUP();
}

TEST_F(DisasmArm64Test, load_store_v_post) {
  SET_UP_ASM();

  COMPARE(ldr(s0, MemOperand(x1, 4, PostIndex)), "ldr s0, [x1], #4");
  COMPARE(ldr(s2, MemOperand(x3, 255, PostIndex)), "ldr s2, [x3], #255");
  COMPARE(ldr(s4, MemOperand(x5, -256, PostIndex)), "ldr s4, [x5], #-256");
  COMPARE(ldr(d6, MemOperand(x7, 8, PostIndex)), "ldr d6, [x7], #8");
  COMPARE(ldr(d8, MemOperand(x9, 255, PostIndex)), "ldr d8, [x9], #255");
  COMPARE(ldr(d10, MemOperand(x11, -256, PostIndex)), "ldr d10, [x11], #-256");

  COMPARE(str(s12, MemOperand(x13, 4, PostIndex)), "str s12, [x13], #4");
  COMPARE(str(s14, MemOperand(x15, 255, PostIndex)), "str s14, [x15], #255");
  COMPARE(str(s16, MemOperand(x17, -256, PostIndex)), "str s16, [x17], #-256");
  COMPARE(str(d18, MemOperand(x19, 8, PostIndex)), "str d18, [x19], #8");
  COMPARE(str(d20, MemOperand(x21, 255, PostIndex)), "str d20, [x21], #255");
  COMPARE(str(d22, MemOperand(x23, -256, PostIndex)), "str d22, [x23], #-256");

  COMPARE(ldr(b0, MemOperand(x1, 4, PostIndex)), "ldr b0, [x1], #4");
  COMPARE(ldr(b2, MemOperand(x3, 255, PostIndex)), "ldr b2, [x3], #255");
  COMPARE(ldr(b4, MemOperand(x5, -256, PostIndex)), "ldr b4, [x5], #-256");
  COMPARE(ldr(h6, MemOperand(x7, 8, PostIndex)), "ldr h6, [x7], #8");
  COMPARE(ldr(h8, MemOperand(x9, 255, PostIndex)), "ldr h8, [x9], #255");
  COMPARE(ldr(h10, MemOperand(x11, -256, PostIndex)), "ldr h10, [x11], #-256");
  COMPARE(ldr(q12, MemOperand(x13, 8, PostIndex)), "ldr q12, [x13], #8");
  COMPARE(ldr(q14, MemOperand(x15, 255, PostIndex)), "ldr q14, [x15], #255");
  COMPARE(ldr(q16, MemOperand(x17, -256, PostIndex)), "ldr q16, [x17], #-256");

  COMPARE(str(b18, MemOperand(x19, 4, PostIndex)), "str b18, [x19], #4");
  COMPARE(str(b20, MemOperand(x21, 255, PostIndex)), "str b20, [x21], #255");
  COMPARE(str(b22, MemOperand(x23, -256, PostIndex)), "str b22, [x23], #-256");
  COMPARE(str(h24, MemOperand(x25, 8, PostIndex)), "str h24, [x25], #8");
  COMPARE(str(h26, MemOperand(x27, 255, PostIndex)), "str h26, [cp], #255");
  COMPARE(str(h28, MemOperand(x29, -256, PostIndex)), "str h28, [fp], #-256");
  COMPARE(str(q30, MemOperand(x1, 8, PostIndex)), "str q30, [x1], #8");
  COMPARE(str(q31, MemOperand(x3, 255, PostIndex)), "str q31, [x3], #255");
  COMPARE(str(q0, MemOperand(x5, -256, PostIndex)), "str q0, [x5], #-256");

  COMPARE(ldr(b24, MemOperand(sp, -1, PreIndex)), "ldr b24, [sp, #-1]!");
  COMPARE(ldr(h25, MemOperand(sp, 2, PreIndex)), "ldr h25, [sp, #2]!");
  COMPARE(ldr(s26, MemOperand(sp, -4, PreIndex)), "ldr s26, [sp, #-4]!");
  COMPARE(ldr(d27, MemOperand(sp, 8, PreIndex)), "ldr d27, [sp, #8]!");
  COMPARE(ldr(q28, MemOperand(sp, -16, PreIndex)), "ldr q28, [sp, #-16]!");

  CLEANUP();
}

TEST_F(DisasmArm64Test, load_store_v_regoffset) {
  SET_UP_ASM();

  COMPARE(ldr(b0, MemOperand(x1, x2)), "ldr b0, [x1, x2]");
  COMPARE(ldr(b1, MemOperand(x2, w3, UXTW)), "ldr b1, [x2, w3, uxtw]");
  COMPARE(ldr(b2, MemOperand(x3, w4, SXTW)), "ldr b2, [x3, w4, sxtw]");
  // We can't assemble this instruction, but we check it disassembles correctly.
  COMPARE(dci(0x3c657883), "ldr b3, [x4, x5, lsl #0]");
  COMPARE(ldr(b30, MemOperand(sp, xzr)), "ldr b30, [sp, xzr]");
  COMPARE(ldr(b31, MemOperand(sp, wzr, UXTW)), "ldr b31, [sp, wzr, uxtw]");

  COMPARE(ldr(h0, MemOperand(x1, x2)), "ldr h0, [x1, x2]");
  COMPARE(ldr(h1, MemOperand(x2, w3, UXTW)), "ldr h1, [x2, w3, uxtw]");
  COMPARE(ldr(h2, MemOperand(x3, w4, SXTW)), "ldr h2, [x3, w4, sxtw]");
  COMPARE(ldr(h3, MemOperand(x4, w5, UXTW, 1)), "ldr h3, [x4, w5, uxtw #1]");
  COMPARE(ldr(h4, MemOperand(x5, w5, SXTW, 1)), "ldr h4, [x5, w5, sxtw #1]");
  COMPARE(ldr(h30, MemOperand(sp, xzr)), "ldr h30, [sp, xzr]");
  COMPARE(ldr(h31, MemOperand(sp, wzr, SXTW, 1)),
          "ldr h31, [sp, wzr, sxtw #1]");

  COMPARE(ldr(s0, MemOperand(x1, x2)), "ldr s0, [x1, x2]");
  COMPARE(ldr(s1, MemOperand(x2, w3, UXTW)), "ldr s1, [x2, w3, uxtw]");
  COMPARE(ldr(s2, MemOperand(x3, w4, SXTW)), "ldr s2, [x3, w4, sxtw]");
  COMPARE(ldr(s3, MemOperand(x4, w5, UXTW, 2)), "ldr s3, [x4, w5, uxtw #2]");
  COMPARE(ldr(s4, MemOperand(x5, w5, SXTW, 2)), "ldr s4, [x5, w5, sxtw #2]");
  COMPARE(ldr(s30, MemOperand(sp, xzr)), "ldr s30, [sp, xzr]");
  COMPARE(ldr(s31, MemOperand(sp, wzr, SXTW, 2)),
          "ldr s31, [sp, wzr, sxtw #2]");

  COMPARE(ldr(d0, MemOperand(x1, x2)), "ldr d0, [x1, x2]");
  COMPARE(ldr(d1, MemOperand(x2, w3, UXTW)), "ldr d1, [x2, w3, uxtw]");
  COMPARE(ldr(d2, MemOperand(x3, w4, SXTW)), "ldr d2, [x3, w4, sxtw]");
  COMPARE(ldr(d3, MemOperand(x4, w5, UXTW, 3)), "ldr d3, [x4, w5, uxtw #3]");
  COMPARE(ldr(d4, MemOperand(x5, w5, SXTW, 3)), "ldr d4, [x5, w5, sxtw #3]");
  COMPARE(ldr(d30, MemOperand(sp, xzr)), "ldr d30, [sp, xzr]");
  COMPARE(ldr(d31, MemOperand(sp, wzr, SXTW, 3)),
          "ldr d31, [sp, wzr, sxtw #3]");

  COMPARE(ldr(q0, MemOperand(x1, x2)), "ldr q0, [x1, x2]");
  COMPARE(ldr(q1, MemOperand(x2, w3, UXTW)), "ldr q1, [x2, w3, uxtw]");
  COMPARE(ldr(q2, MemOperand(x3, w4, SXTW)), "ldr q2, [x3, w4, sxtw]");
  COMPARE(ldr(q3, MemOperand(x4, w5, UXTW, 4)), "ldr q3, [x4, w5, uxtw #4]");
  COMPARE(ldr(q4, MemOperand(x5, w5, SXTW, 4)), "ldr q4, [x5, w5, sxtw #4]");
  COMPARE(ldr(q30, MemOperand(sp, xzr)), "ldr q30, [sp, xzr]");
  COMPARE(ldr(q31, MemOperand(sp, wzr, SXTW, 4)),
          "ldr q31, [sp, wzr, sxtw #4]");

  COMPARE(str(b0, MemOperand(x1, x2)), "str b0, [x1, x2]");
  COMPARE(str(b1, MemOperand(x2, w3, UXTW)), "str b1, [x2, w3, uxtw]");
  COMPARE(str(b2, MemOperand(x3, w4, SXTW)), "str b2, [x3, w4, sxtw]");
  // We can't assemble this instruction, but we check it disassembles correctly.
  COMPARE(dci(0x3c257883), "str b3, [x4, x5, lsl #0]");
  COMPARE(str(b30, MemOperand(sp, xzr)), "str b30, [sp, xzr]");
  COMPARE(str(b31, MemOperand(sp, wzr, UXTW)), "str b31, [sp, wzr, uxtw]");

  COMPARE(str(h0, MemOperand(x1, x2)), "str h0, [x1, x2]");
  COMPARE(str(h1, MemOperand(x2, w3, UXTW)), "str h1, [x2, w3, uxtw]");
  COMPARE(str(h2, MemOperand(x3, w4, SXTW)), "str h2, [x3, w4, sxtw]");
  COMPARE(str(h3, MemOperand(x4, w5, UXTW, 1)), "str h3, [x4, w5, uxtw #1]");
  COMPARE(str(h4, MemOperand(x5, w5, SXTW, 1)), "str h4, [x5, w5, sxtw #1]");
  COMPARE(str(h30, MemOperand(sp, xzr)), "str h30, [sp, xzr]");
  COMPARE(str(h31, MemOperand(sp, wzr, SXTW, 1)),
          "str h31, [sp, wzr, sxtw #1]");

  COMPARE(str(s0, MemOperand(x1, x2)), "str s0, [x1, x2]");
  COMPARE(str(s1, MemOperand(x2, w3, UXTW)), "str s1, [x2, w3, uxtw]");
  COMPARE(str(s2, MemOperand(x3, w4, SXTW)), "str s2, [x3, w4, sxtw]");
  COMPARE(str(s3, MemOperand(x4, w5, UXTW, 2)), "str s3, [x4, w5, uxtw #2]");
  COMPARE(str(s4, MemOperand(x5, w5, SXTW, 2)), "str s4, [x5, w5, sxtw #2]");
  COMPARE(str(s30, MemOperand(sp, xzr)), "str s30, [sp, xzr]");
  COMPARE(str(s31, MemOperand(sp, wzr, SXTW, 2)),
          "str s31, [sp, wzr, sxtw #2]");

  COMPARE(str(d0, MemOperand(x1, x2)), "str d0, [x1, x2]");
  COMPARE(str(d1, MemOperand(x2, w3, UXTW)), "str d1, [x2, w3, uxtw]");
  COMPARE(str(d2, MemOperand(x3, w4, SXTW)), "str d2, [x3, w4, sxtw]");
  COMPARE(str(d3, MemOperand(x4, w5, UXTW, 3)), "str d3, [x4, w5, uxtw #3]");
  COMPARE(str(d4, MemOperand(x5, w5, SXTW, 3)), "str d4, [x5, w5, sxtw #3]");
  COMPARE(str(d30, MemOperand(sp, xzr)), "str d30, [sp, xzr]");
  COMPARE(str(d31, MemOperand(sp, wzr, SXTW, 3)),
          "str d31, [sp, wzr, sxtw #3]");

  COMPARE(str(q0, MemOperand(x1, x2)), "str q0, [x1, x2]");
  COMPARE(str(q1, MemOperand(x2, w3, UXTW)), "str q1, [x2, w3, uxtw]");
  COMPARE(str(q2, MemOperand(x3, w4, SXTW)), "str q2, [x3, w4, sxtw]");
  COMPARE(str(q3, MemOperand(x4, w5, UXTW, 4)), "str q3, [x4, w5, uxtw #4]");
  COMPARE(str(q4, MemOperand(x5, w5, SXTW, 4)), "str q4, [x5, w5, sxtw #4]");
  COMPARE(str(q30, MemOperand(sp, xzr)), "str q30, [sp, xzr]");
  COMPARE(str(q31, MemOperand(sp, wzr, SXTW, 4)),
          "str q31, [sp, wzr, sxtw #4]");

  CLEANUP();
}

TEST_F(DisasmArm64Test, load_store_unscaled) {
  SET_UP_ASM();

  COMPARE(ldr(w0, MemOperand(x1, 1)), "ldur w0, [x1, #1]");
  COMPARE(ldr(w2, MemOperand(x3, -1)), "ldur w2, [x3, #-1]");
  COMPARE(ldr(w4, MemOperand(x5, 255)), "ldur w4, [x5, #255]");
  COMPARE(ldr(w6, MemOperand(x7, -256)), "ldur w6, [x7, #-256]");
  COMPARE(ldr(x8, MemOperand(x9, 1)), "ldur x8, [x9, #1]");
  COMPARE(ldr(x10, MemOperand(x11, -1)), "ldur x10, [x11, #-1]");
  COMPARE(ldr(x12, MemOperand(x13, 255)), "ldur x12, [x13, #255]");
  COMPARE(ldr(x14, MemOperand(x15, -256)), "ldur x14, [x15, #-256]");
  COMPARE(str(w16, MemOperand(x17, 1)), "stur w16, [x17, #1]");
  COMPARE(str(w18, MemOperand(x19, -1)), "stur w18, [x19, #-1]");
  COMPARE(str(w20, MemOperand(x21, 255)), "stur w20, [x21, #255]");
  COMPARE(str(w22, MemOperand(x23, -256)), "stur w22, [x23, #-256]");
  COMPARE(str(x24, MemOperand(x25, 1)), "stur x24, [x25, #1]");
  COMPARE(str(x26, MemOperand(x27, -1)), "stur x26, [cp, #-1]");
  COMPARE(str(x28, MemOperand(x29, 255)), "stur x28, [fp, #255]");
  COMPARE(str(x30, MemOperand(x0, -256)), "stur lr, [x0, #-256]");
  COMPARE(ldr(w0, MemOperand(sp, 1)), "ldur w0, [sp, #1]");
  COMPARE(str(x1, MemOperand(sp, -1)), "stur x1, [sp, #-1]");
  COMPARE(ldrb(w2, MemOperand(x3, -2)), "ldurb w2, [x3, #-2]");
  COMPARE(ldrsb(w4, MemOperand(x5, -3)), "ldursb w4, [x5, #-3]");
  COMPARE(ldrsb(x6, MemOperand(x7, -4)), "ldursb x6, [x7, #-4]");
  COMPARE(ldrh(w8, MemOperand(x9, -5)), "ldurh w8, [x9, #-5]");
  COMPARE(ldrsh(w10, MemOperand(x11, -6)), "ldursh w10, [x11, #-6]");
  COMPARE(ldrsh(x12, MemOperand(x13, -7)), "ldursh x12, [x13, #-7]");
  COMPARE(ldrsw(x14, MemOperand(x15, -8)), "ldursw x14, [x15, #-8]");

  COMPARE(ldr(b0, MemOperand(x1, -1)), "ldur b0, [x1, #-1]");
  COMPARE(ldr(h2, MemOperand(x3, -1)), "ldur h2, [x3, #-1]");
  COMPARE(ldr(s4, MemOperand(x5, 255)), "ldur s4, [x5, #255]");
  COMPARE(ldr(d6, MemOperand(x7, -256)), "ldur d6, [x7, #-256]");
  COMPARE(ldr(q8, MemOperand(x9, 1)), "ldur q8, [x9, #1]");
  COMPARE(str(b16, MemOperand(x17, -1)), "stur b16, [x17, #-1]");
  COMPARE(str(h18, MemOperand(x19, -1)), "stur h18, [x19, #-1]");
  COMPARE(str(s20, MemOperand(x21, 255)), "stur s20, [x21, #255]");
  COMPARE(str(d22, MemOperand(x23, -256)), "stur d22, [x23, #-256]");
  COMPARE(str(q24, MemOperand(x25, 1)), "stur q24, [x25, #1]");

  CLEANUP();
}

TEST_F(DisasmArm64Test, load_store_pair) {
  SET_UP_ASM();

  COMPARE(ldp(w0, w1, MemOperand(x2)), "ldp w0, w1, [x2]");
  COMPARE(ldp(x3, x4, MemOperand(x5)), "ldp x3, x4, [x5]");
  COMPARE(ldp(w6, w7, MemOperand(x8, 4)), "ldp w6, w7, [x8, #4]");
  COMPARE(ldp(x9, x10, MemOperand(x11, 8)), "ldp x9, x10, [x11, #8]");
  COMPARE(ldp(w12, w13, MemOperand(x14, 252)), "ldp w12, w13, [x14, #252]");
  COMPARE(ldp(x15, x16, MemOperand(x17, 504)), "ldp x15, x16, [x17, #504]");
  COMPARE(ldp(w18, w19, MemOperand(x20, -256)), "ldp w18, w19, [x20, #-256]");
  COMPARE(ldp(x21, x22, MemOperand(x23, -512)), "ldp x21, x22, [x23, #-512]");
  COMPARE(ldp(w24, w25, MemOperand(x26, 252, PreIndex)),
          "ldp w24, w25, [x26, #252]!");
  COMPARE(ldp(cp, x28, MemOperand(fp, 504, PreIndex)),
          "ldp cp, x28, [fp, #504]!");
  COMPARE(ldp(w30, w0, MemOperand(x1, -256, PreIndex)),
          "ldp w30, w0, [x1, #-256]!");
  COMPARE(ldp(x2, x3, MemOperand(x4, -512, PreIndex)),
          "ldp x2, x3, [x4, #-512]!");
  COMPARE(ldp(w5, w6, MemOperand(x7, 252, PostIndex)),
          "ldp w5, w6, [x7], #252");
  COMPARE(ldp(x8, x9, MemOperand(x10, 504, PostIndex)),
          "ldp x8, x9, [x10], #504");
  COMPARE(ldp(w11, w12, MemOperand(x13, -256, PostIndex)),
          "ldp w11, w12, [x13], #-256");
  COMPARE(ldp(x14, x15, MemOperand(x16, -512, PostIndex)),
          "ldp x14, x15, [x16], #-512");

  COMPARE(ldp(s17, s18, MemOperand(x19)), "ldp s17, s18, [x19]");
  COMPARE(ldp(s20, s21, MemOperand(x22, 252)), "ldp s20, s21, [x22, #252]");
  COMPARE(ldp(s23, s24, MemOperand(x25, -256)), "ldp s23, s24, [x25, #-256]");
  COMPARE(ldp(s26, s27, MemOperand(x28, 252, PreIndex)),
          "ldp s26, s27, [x28, #252]!");
"""


```