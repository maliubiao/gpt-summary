Response:
Let's break down the thought process for analyzing the provided C++ header file snippet.

1. **Understand the Goal:** The request asks for a summary of the functionality of the given C++ header file, `assembler-s390.h`, focusing on its purpose within V8, its potential relationship to JavaScript, and common programming errors it might help avoid. It also specifically asks about Torque and code logic.

2. **Initial Scan and Keyword Recognition:** Quickly scan the code for recognizable patterns and keywords. I see:
    * `#define`:  Lots of macros. This strongly suggests code generation and abstraction over machine instructions.
    * `void name(...)`: Function declarations. These seem to be related to emitting machine code.
    * `emit2bytes`, `emit4bytes`, `emit6bytes`:  Functions for writing raw byte sequences. This confirms the assembler's role in generating machine code.
    * `Register`, `MemOperand`, `Operand`, `Condition`: Data types representing CPU registers, memory locations, operands, and conditional flags – all standard assembly concepts.
    * `Label*`:  Pointers to labels, crucial for branching and control flow in assembly.
    * `S390_SI_OPCODE_LIST`, `S390_SIY_OPCODE_LIST`, etc.:  Lists of opcodes. This reinforces the idea of generating specific S390 instructions.
    * `branchOnCond`, `b`, `beq`, `bne`, etc.: Functions for generating branch instructions.
    * `Align`, `DataAlign`, `CodeTargetAlign`: Functions for memory alignment, important for performance.
    * `breakpoint`:  A function to insert a breakpoint, used for debugging.
    * `call`, `jump`: Functions for generating function calls and jumps.
    * `RecordDeoptReason`: Related to deoptimization, a V8-specific concept.
    * `db`, `dh`, `dd`, `dq`, `dp`: Functions for emitting raw data of different sizes.
    * `instr_at`, `instr_at_put`, `instr_length_at`: Functions for inspecting and modifying existing instructions.
    * `EnsureSpaceFor`, `GrowBuffer`:  Memory management for the instruction buffer.
    * `RelocInfo`: Relocation information, needed when generating code that will be loaded at a dynamic address.
    * `Scratch registers`:  Temporary registers used during code generation.

3. **Formulate a High-Level Summary:** Based on the keywords and patterns, the core functionality is clearly about generating machine code for the s390 architecture within the V8 JavaScript engine. It provides an abstraction layer over raw machine instructions.

4. **Address Specific Questions:**
    * **Torque:** The prompt asks if the file is a Torque file based on the `.tq` extension. The provided snippet doesn't have that extension, so the answer is "no." Explain what Torque is in the V8 context.
    * **Relationship to JavaScript:** How does this assembly generation relate to JavaScript?  V8 compiles JavaScript code into machine code for execution. This assembler is a key component in that process for the s390 architecture. Provide a simplified JavaScript example that *could* lead to the generation of s390 assembly (e.g., a simple addition). Emphasize that the *exact* assembly generated is complex and depends on V8's internal optimizations.
    * **Code Logic Inference:** Focus on a simple, self-contained logical block. The `siy_format` function is a good candidate.
        * **Input Assumption:**  Provide concrete example values for `op`, `f1`, `f2`, `f3`. Make sure they adhere to the `DCHECK` constraints.
        * **Output Calculation:** Manually calculate the `code` based on the bitfield manipulations. Explain each step. Present the expected hexadecimal output.
    * **Common Programming Errors:** Think about what kinds of errors this assembler *helps* avoid compared to writing raw assembly. Focus on:
        * **Incorrect Opcode Encoding:** The macros and format functions ensure correct encoding.
        * **Incorrect Operand Size/Type:** The type system and `DCHECK`s help catch these.
        * **Displacement/Offset Errors:**  The `MemOperand` abstraction helps manage these.
        * **Forgetting Relocation:** V8's infrastructure handles this, but a raw assembler would require manual management.

5. **Structure the Answer:** Organize the findings logically. Start with a general summary, then address the specific points from the prompt. Use clear headings and formatting. Provide concrete examples for the code logic and common errors.

6. **Refine and Elaborate:** Review the drafted answer. Are the explanations clear and concise? Are the examples helpful? Add details where needed (e.g., explaining what bitfields and masking are in the `siy_format` example). Emphasize the abstraction provided by the assembler.

7. **Final Check:**  Read through the entire response to ensure it directly answers all parts of the prompt and is technically accurate. Confirm the "Part 2" aspect and its implications (building upon previous knowledge).

Self-Correction during the process:

* **Initial thought:** Focus only on the individual functions.
* **Correction:** Realize that the overarching purpose of the file is the most important thing to convey first. The individual functions support this purpose.
* **Initial thought:** Try to provide very specific assembly examples tied to JavaScript.
* **Correction:**  Recognize that the exact assembly is highly dependent on V8 internals and optimization levels. Provide a simplified, illustrative JavaScript example instead.
* **Initial thought:** Just list the functions.
* **Correction:** Group the functions by their purpose (instruction formatting, branching, alignment, etc.) to provide a more structured understanding.

By following this structured thought process, including the self-correction step, we can arrive at a comprehensive and accurate answer to the request.
这是v8源代码文件`v8/src/codegen/s390/assembler-s390.h`的第二部分，延续了第一部分关于s390架构汇编器的定义。让我们归纳一下这部分代码的功能：

**核心功能延续：定义用于生成s390架构机器码的汇编器接口**

这部分代码继续定义了`Assembler`类的方法，这些方法对应着s390架构的各种指令。它提供了一种高级的、类型安全的方式来生成机器码，避免了直接操作原始字节的复杂性。

**具体功能点归纳：**

1. **SIY, RRS, RIS, SIL, RIE, SS 等指令格式的定义和生成:**
   - 延续了第一部分定义指令格式和生成函数的模式。
   - 针对 SIY, RRS, RIS, SIL, RIE (D, E, F子格式), SS (A子格式) 等不同的指令格式，定义了相应的 `*_format` 函数（如 `siy_format`, `rrs_format` 等），这些函数负责将操作码和操作数编码成二进制机器码。
   - 提供了宏 (`DECLARE_S390_*_INSTRUCTIONS`) 来简化定义指令生成函数的过程。这些宏会遍历预定义的指令列表 (`S390_*_OPCODE_LIST`)，并为每条指令生成对应的 C++ 方法。
   - 这些方法接收 `Register`, `MemOperand`, `Operand`, `Condition` 等类型的参数，代表了s390架构的寄存器、内存操作数、立即数和条件码。

2. **分支指令的便捷封装:**
   - 提供了多种方便的分支指令生成函数，如 `b` (无条件跳转), `branchOnCond` (条件跳转), `beq` (相等跳转), `bne` (不等跳转), `blt`, `ble`, `bgt`, `bge` 等。
   - 这些函数允许使用 `Label` 对象作为跳转目标，汇编器会自动计算跳转偏移量。
   - 提供了短跳转 (`bc_short`) 和长跳转 (`bc_long`) 的选项。
   - 针对寄存器间接跳转，也提供了相应的封装，如 `b(Condition cond, Register r)`.

3. **循环和条件分支的辅助指令:**
   - 提供了 `brxh` 和 `brxhg` 指令的封装，用于循环控制。

4. **向量寄存器操作指令的定义和生成:**
   - 定义了用于生成向量寄存器（DoubleRegister）操作指令的方法，涵盖了 VRR (寄存器-寄存器), VRX (寄存器-索引内存), VRS (寄存器-基址变址内存), VRI (寄存器-立即数) 等指令格式。
   - 使用了 `DECLARE_VRR_A_INSTRUCTIONS`, `DECLARE_VRR_C_INSTRUCTIONS` 等宏来简化定义过程。
   - 这些指令用于 SIMD (单指令多数据) 操作。

5. **加载地址指令:**
   - 提供了 `larl` 和 `lgrl` 指令的封装，用于加载标签的地址到寄存器。

6. **异常和调试支持:**
   - 提供了 `stop` 指令的封装，用于产生异常。
   - 提供了 `bkpt` 指令的封装，用于插入断点。

7. **NOP 指令:**
   - 提供了 `nop` 指令的封装，可以插入不同类型的 NOP 指令，用于代码对齐或标记特定状态。

8. **DUMY 指令:**
   - 提供了 `dumy` 指令的封装，其功能可能与内存访问或性能测试有关。

9. **代码大小计算:**
   - 提供了 `SizeOfCodeGeneratedSince` 函数，用于计算自指定标签以来生成的代码大小。

10. **记录反优化原因:**
    - 提供了 `RecordDeoptReason` 函数，用于记录代码反优化的原因，这对于性能分析和调试非常重要。

11. **数据写入:**
    - 提供了 `db`, `dh`, `dd`, `dq`, `dp` 等函数，用于在代码流中写入单字节、双字节、四字节、八字节和指针大小的数据。这通常用于创建常量表或其他内联数据。

12. **指令读取和修改:**
    - 提供了 `instr_at`, `instr_at_put`, `instr_length_at` 等函数，用于读取、修改和获取指定位置的指令。这在代码修补或动态代码生成中可能用到。

13. **静态方法:**
    - 提供了一些静态方法，如 `GetCondition`, `IsBranch`, `Is64BitLoadIntoIP`, `IsCmpRegister`, `IsCmpImmediate`, `IsNop`，用于分析现有的机器指令。

14. **缓冲区管理:**
    - 提供了 `EnsureSpaceFor` 函数，确保有足够的空间来写入指令。
    - 内部使用了 `CheckBuffer` 和 `GrowBuffer` 等方法来动态管理汇编代码的缓冲区。

15. **重定位信息:**
    - 提供了 `EmitRelocations` 函数来处理重定位信息，这对于生成可以加载到任意内存地址的代码至关重要。
    - 使用 `RelocInfoWriter` 来管理重定位信息。

16. **标签处理:**
    - 提供了 `print`, `max_reach_from`, `bind_to`, `next` 等方法来处理代码标签。

17. **辅助类:**
    - 定义了 `EnsureSpace` 和 `UseScratchRegisterScope` 等辅助类，用于资源管理和代码生成过程中的辅助操作。

**总结:**

这部分 `assembler-s390.h` 代码的核心职责是继续扩展和完善 s390 架构的汇编器功能。它通过提供大量的指令生成函数、便捷的跳转封装、向量指令支持、以及缓冲区管理和重定位机制，使得 V8 能够高效且安全地生成针对 s390 架构的优化机器码，从而执行 JavaScript 代码。这部分代码是 V8 在 s390 平台上运行的关键组成部分。

**关于 .tq 结尾：**

正如第一部分所述，如果 `v8/src/codegen/s390/assembler-s390.h` 以 `.tq` 结尾，那么它确实是一个 V8 Torque 源代码文件。Torque 是一种 V8 内部使用的领域特定语言，用于更安全、更易于维护地生成 TurboFan 编译器中的代码。然而，当前提供的文件名是 `.h`，表示这是一个 C++ 头文件。

**与 JavaScript 功能的关系：**

`assembler-s390.h` 中定义的汇编器类直接参与了将 JavaScript 代码转换为机器码的过程。当 V8 的 TurboFan 编译器或其他代码生成器需要生成 s390 架构的指令时，它们会使用 `Assembler` 类提供的接口。

**JavaScript 例子：**

一个简单的 JavaScript 加法运算最终会被编译成一系列的机器指令，其中可能就包括这里定义的汇编器方法生成的指令。

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
```

当 V8 编译 `add` 函数时，它可能会生成如下类似的 s390 汇编指令（这只是一个简化的例子，实际生成的代码会更复杂）：

```assembly
  // 假设 a 和 b 存储在寄存器 r2 和 r3 中
  agr r1, r2, r3  // 将 r2 和 r3 的值相加，结果存储到 r1
  br r14         // 返回
```

上述 `agr` 指令就可能通过 `Assembler` 类的某个方法（例如，一个名为 `agr` 的方法）生成。

**代码逻辑推理示例：**

假设输入以下调用：

```c++
Assembler masm;
Register r1 = r1;
Register r2 = r2;
Operand immediate(100);
masm.ahi(r1, r2, immediate);
```

根据 `DECLARE_S390_RRIL_INSTRUCTIONS` 宏和 `rril_format` 函数的定义，`ahi` 方法会调用 `rril_format`，将操作码、寄存器和立即数编码成 6 字节的机器码。

**假设输入：**
- `op_name` (对应 `ahi` 的操作码) 的值为 `0xB304`
- `r1.code()` 的值为 `1` (代表寄存器 r1)
- `r3.code()` 的值为 `2` (代表寄存器 r2)
- `i4.immediate()` 的值为 `100` (0x64)

**输出：**
`rril_format` 函数会将这些值组合成一个 6 字节的十六进制数，例如： `B3 04 01 02 00 64` （字节顺序可能需要根据实际的 endianness 调整）。 `emit6bytes` 函数会将这个 6 字节的值写入到代码流中。

**用户常见的编程错误：**

使用汇编器时，用户可能会犯以下错误，但 V8 的汇编器设计在一定程度上可以帮助避免这些错误：

1. **使用错误的寄存器或操作数类型：**
   - 汇编器通过类型系统（如 `Register`, `MemOperand`）来限制操作数的类型，如果传入错误的类型，编译器会报错。

   ```c++
   // 错误示例：尝试将一个立即数作为内存操作数传递 (假设 MemOperand 需要寄存器)
   // masm.lw(r1, Operand(10)); // 这会导致编译错误，因为 Operand(10) 不是 MemOperand
   ```

2. **操作码编码错误：**
   - 汇编器的方法封装了操作码的编码细节，用户不需要手动指定操作码的值，从而避免了编码错误。

3. **跳转偏移量计算错误：**
   - 使用 `Label` 对象进行跳转时，汇编器会自动计算偏移量，避免了手动计算可能导致的错误。

   ```c++
   Label target;
   masm.b(&target);
   // ... 一些代码 ...
   masm.bind(&target);
   ```

4. **忘记处理重定位：**
   - V8 的汇编器会自动处理需要重定位的地址，用户通常不需要显式地管理重定位信息。

**总结这部分的功能：**

这部分 `v8/src/codegen/s390/assembler-s390.h` 文件的主要功能是**继续定义和实现用于生成 s390 架构机器码的汇编器接口**。它涵盖了多种指令格式的生成，提供了便捷的分支指令封装，支持向量寄存器操作，并提供了异常处理、调试支持、数据写入、指令读取修改等辅助功能。通过抽象底层机器指令的细节，该汇编器使得 V8 能够更安全、高效地为 s390 平台生成优化的代码。它是 V8 在 s390 架构上执行 JavaScript 代码的关键组成部分。

### 提示词
```
这是目录为v8/src/codegen/s390/assembler-s390.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/s390/assembler-s390.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```c
\
  }                                                                    \
  void name(const MemOperand& opnd, const Operand& i2) {               \
    name(i2, opnd.getBaseRegister(), Operand(opnd.getDisplacement())); \
  }
  S390_SI_OPCODE_LIST(DECLARE_S390_SI_INSTRUCTIONS)
#undef DECLARE_S390_SI_INSTRUCTIONS

  inline void siy_format(Opcode op, int f1, int f2, int f3) {
    DCHECK(is_uint20(f3) || is_int20(f3));
    DCHECK(is_uint16(op));
    DCHECK(is_uint8(f1) || is_int8(f1));
    uint64_t code = getfield<uint64_t, 6, 0, 8>(op >> 8) |
                    getfield<uint64_t, 6, 8, 16>(f1) |
                    getfield<uint64_t, 6, 16, 20>(f2) |
                    getfield<uint64_t, 6, 20, 32>(f3) |
                    getfield<uint64_t, 6, 32, 40>(f3 >> 12) |
                    getfield<uint64_t, 6, 40, 48>(op & 0x00FF);
    emit6bytes(code);
  }

#define DECLARE_S390_SIY_INSTRUCTIONS(name, op_name, op_value)         \
  void name(const Operand& i2, Register b1, const Operand& d1) {       \
    siy_format(op_name, i2.immediate(), b1.code(), d1.immediate());    \
  }                                                                    \
  void name(const MemOperand& opnd, const Operand& i2) {               \
    name(i2, opnd.getBaseRegister(), Operand(opnd.getDisplacement())); \
  }
  S390_SIY_OPCODE_LIST(DECLARE_S390_SIY_INSTRUCTIONS)
#undef DECLARE_S390_SIY_INSTRUCTIONS

  inline void rrs_format(Opcode op, int f1, int f2, int f3, int f4, int f5) {
    DCHECK(is_uint12(f4));
    DCHECK(is_uint16(op));
    uint64_t code =
        getfield<uint64_t, 6, 0, 8>(op >> 8) |
        getfield<uint64_t, 6, 8, 12>(f1) | getfield<uint64_t, 6, 12, 16>(f2) |
        getfield<uint64_t, 6, 16, 20>(f3) | getfield<uint64_t, 6, 20, 32>(f4) |
        getfield<uint64_t, 6, 32, 36>(f5) |
        getfield<uint64_t, 6, 40, 48>(op & 0x00FF);
    emit6bytes(code);
  }

#define DECLARE_S390_RRS_INSTRUCTIONS(name, op_name, op_value)                 \
  void name(Register r1, Register r2, Register b4, const Operand& d4,          \
            Condition m3) {                                                    \
    rrs_format(op_name, r1.code(), r2.code(), b4.code(), d4.immediate(), m3);  \
  }                                                                            \
  void name(Register r1, Register r2, Condition m3, const MemOperand& opnd) {  \
    name(r1, r2, opnd.getBaseRegister(), Operand(opnd.getDisplacement()), m3); \
  }
  S390_RRS_OPCODE_LIST(DECLARE_S390_RRS_INSTRUCTIONS)
#undef DECLARE_S390_RRS_INSTRUCTIONS

  inline void ris_format(Opcode op, int f1, int f2, int f3, int f4, int f5) {
    DCHECK(is_uint12(f3));
    DCHECK(is_uint16(op));
    DCHECK(is_uint8(f5));
    uint64_t code =
        getfield<uint64_t, 6, 0, 8>(op >> 8) |
        getfield<uint64_t, 6, 8, 12>(f1) | getfield<uint64_t, 6, 12, 16>(f2) |
        getfield<uint64_t, 6, 16, 20>(f3) | getfield<uint64_t, 6, 20, 32>(f4) |
        getfield<uint64_t, 6, 32, 40>(f5) |
        getfield<uint64_t, 6, 40, 48>(op & 0x00FF);
    emit6bytes(code);
  }

#define DECLARE_S390_RIS_INSTRUCTIONS(name, op_name, op_value)                 \
  void name(Register r1, Condition m3, Register b4, const Operand& d4,         \
            const Operand& i2) {                                               \
    ris_format(op_name, r1.code(), m3, b4.code(), d4.immediate(),              \
               i2.immediate());                                                \
  }                                                                            \
  void name(Register r1, const Operand& i2, Condition m3,                      \
            const MemOperand& opnd) {                                          \
    name(r1, m3, opnd.getBaseRegister(), Operand(opnd.getDisplacement()), i2); \
  }
  S390_RIS_OPCODE_LIST(DECLARE_S390_RIS_INSTRUCTIONS)
#undef DECLARE_S390_RIS_INSTRUCTIONS

  inline void sil_format(Opcode op, int f1, int f2, int f3) {
    DCHECK(is_uint12(f2));
    DCHECK(is_uint16(op));
    DCHECK(is_uint16(f3));
    uint64_t code =
        getfield<uint64_t, 6, 0, 16>(op) | getfield<uint64_t, 6, 16, 20>(f1) |
        getfield<uint64_t, 6, 20, 32>(f2) | getfield<uint64_t, 6, 32, 48>(f3);
    emit6bytes(code);
  }

#define DECLARE_S390_SIL_INSTRUCTIONS(name, op_name, op_value)         \
  void name(Register b1, const Operand& d1, const Operand& i2) {       \
    sil_format(op_name, b1.code(), d1.immediate(), i2.immediate());    \
  }                                                                    \
  void name(const MemOperand& opnd, const Operand& i2) {               \
    name(opnd.getBaseRegister(), Operand(opnd.getDisplacement()), i2); \
  }
  S390_SIL_OPCODE_LIST(DECLARE_S390_SIL_INSTRUCTIONS)
#undef DECLARE_S390_SIL_INSTRUCTIONS

  inline void rie_d_format(Opcode opcode, int f1, int f2, int f3, int f4) {
    uint32_t op1 = opcode >> 8;
    uint32_t op2 = opcode & 0xff;
    uint64_t code =
        getfield<uint64_t, 6, 0, 8>(op1) | getfield<uint64_t, 6, 8, 12>(f1) |
        getfield<uint64_t, 6, 12, 16>(f2) | getfield<uint64_t, 6, 16, 32>(f3) |
        getfield<uint64_t, 6, 32, 40>(f4) | getfield<uint64_t, 6, 40, 48>(op2);
    emit6bytes(code);
  }

#define DECLARE_S390_RIE_D_INSTRUCTIONS(name, op_name, op_value)    \
  void name(Register r1, Register r3, const Operand& i2) {          \
    rie_d_format(op_name, r1.code(), r3.code(), i2.immediate(), 0); \
  }
  S390_RIE_D_OPCODE_LIST(DECLARE_S390_RIE_D_INSTRUCTIONS)
#undef DECLARE_S390_RIE_D_INSTRUCTIONS

  inline void rie_e_format(Opcode opcode, int f1, int f2, int f3) {
    uint32_t op1 = opcode >> 8;
    uint32_t op2 = opcode & 0xff;
    uint64_t code =
        getfield<uint64_t, 6, 0, 8>(op1) | getfield<uint64_t, 6, 8, 12>(f1) |
        getfield<uint64_t, 6, 12, 16>(f2) | getfield<uint64_t, 6, 16, 32>(f3) |
        getfield<uint64_t, 6, 40, 48>(op2);
    emit6bytes(code);
  }

#define DECLARE_S390_RIE_E_INSTRUCTIONS(name, op_name, op_value) \
  void name(Register r1, Register r3, const Operand& i2) {       \
    rie_e_format(op_name, r1.code(), r3.code(), i2.immediate()); \
  }
  S390_RIE_E_OPCODE_LIST(DECLARE_S390_RIE_E_INSTRUCTIONS)
#undef DECLARE_S390_RIE_E_INSTRUCTIONS

  inline void rie_f_format(Opcode opcode, int f1, int f2, int f3, int f4,
                           int f5) {
    uint32_t op1 = opcode >> 8;
    uint32_t op2 = opcode & 0xff;
    uint64_t code =
        getfield<uint64_t, 6, 0, 8>(op1) | getfield<uint64_t, 6, 8, 12>(f1) |
        getfield<uint64_t, 6, 12, 16>(f2) | getfield<uint64_t, 6, 16, 24>(f3) |
        getfield<uint64_t, 6, 24, 32>(f4) | getfield<uint64_t, 6, 32, 40>(f5) |
        getfield<uint64_t, 6, 40, 48>(op2);
    emit6bytes(code);
  }

#define DECLARE_S390_RIE_F_INSTRUCTIONS(name, op_name, op_value)        \
  void name(Register dst, Register src, const Operand& startBit,        \
            const Operand& endBit, const Operand& shiftAmt) {           \
    DCHECK(is_uint8(startBit.immediate()));                             \
    DCHECK(is_uint8(endBit.immediate()));                               \
    DCHECK(is_uint8(shiftAmt.immediate()));                             \
    rie_f_format(op_name, dst.code(), src.code(), startBit.immediate(), \
                 endBit.immediate(), shiftAmt.immediate());             \
  }
  S390_RIE_F_OPCODE_LIST(DECLARE_S390_RIE_F_INSTRUCTIONS)
#undef DECLARE_S390_RIE_F_INSTRUCTIONS

  inline void ss_a_format(Opcode op, int f1, int f2, int f3, int f4, int f5) {
    DCHECK(is_uint12(f5));
    DCHECK(is_uint12(f3));
    DCHECK(is_uint8(f1));
    DCHECK(is_uint8(op));
    uint64_t code =
        getfield<uint64_t, 6, 0, 8>(op) | getfield<uint64_t, 6, 8, 16>(f1) |
        getfield<uint64_t, 6, 16, 20>(f2) | getfield<uint64_t, 6, 20, 32>(f3) |
        getfield<uint64_t, 6, 32, 36>(f4) | getfield<uint64_t, 6, 36, 48>(f5);
    emit6bytes(code);
  }

#define DECLARE_S390_SS_A_INSTRUCTIONS(name, op_name, op_value)              \
  void name(Register b1, const Operand& d1, Register b2, const Operand& d2,  \
            const Operand& length) {                                         \
    ss_a_format(op_name, length.immediate(), b1.code(), d1.immediate(),      \
                b2.code(), d2.immediate());                                  \
  }                                                                          \
  void name(const MemOperand& opnd1, const MemOperand& opnd2,                \
            const Operand& length) {                                         \
    ss_a_format(op_name, length.immediate(), opnd1.getBaseRegister().code(), \
                opnd1.getDisplacement(), opnd2.getBaseRegister().code(),     \
                opnd2.getDisplacement());                                    \
  }
  S390_SS_A_OPCODE_LIST(DECLARE_S390_SS_A_INSTRUCTIONS)
#undef DECLARE_S390_SS_A_INSTRUCTIONS

  // Helper for unconditional branch to Label with update to save register
  void b(Register r, Label* l) {
    int32_t halfwords = branch_offset(l) / 2;
    brasl(r, Operand(halfwords));
  }

  // Conditional Branch Instruction - Generates either BRC / BRCL
  void branchOnCond(Condition c, int branch_offset, bool is_bound = false,
                    bool force_long_branch = false);

  // Helpers for conditional branch to Label
  void b(Condition cond, Label* l, Label::Distance dist = Label::kFar,
         bool force_long_branch = false) {
    branchOnCond(cond, branch_offset(l),
                 l->is_bound() || (dist == Label::kNear), force_long_branch);
  }

  void bc_short(Condition cond, Label* l, Label::Distance dist = Label::kFar) {
    b(cond, l, Label::kNear);
  }
  void bc_long(Condition cond, Label* l) { b(cond, l, Label::kFar, true); }
  // Helpers for conditional branch to Label
  void beq(Label* l, Label::Distance dist = Label::kFar) { b(eq, l, dist); }
  void bne(Label* l, Label::Distance dist = Label::kFar) { b(ne, l, dist); }
  void blt(Label* l, Label::Distance dist = Label::kFar) { b(lt, l, dist); }
  void ble(Label* l, Label::Distance dist = Label::kFar) { b(le, l, dist); }
  void bgt(Label* l, Label::Distance dist = Label::kFar) { b(gt, l, dist); }
  void bge(Label* l, Label::Distance dist = Label::kFar) { b(ge, l, dist); }
  void b(Label* l, Label::Distance dist = Label::kFar) { b(al, l, dist); }
  void jmp(Label* l, Label::Distance dist = Label::kFar) { b(al, l, dist); }
  void bunordered(Label* l, Label::Distance dist = Label::kFar) {
    b(unordered, l, dist);
  }
  void bordered(Label* l, Label::Distance dist = Label::kFar) {
    b(ordered, l, dist);
  }

  // Helpers for conditional indirect branch off register
  void b(Condition cond, Register r) { bcr(cond, r); }
  void beq(Register r) { b(eq, r); }
  void bne(Register r) { b(ne, r); }
  void blt(Register r) { b(lt, r); }
  void ble(Register r) { b(le, r); }
  void bgt(Register r) { b(gt, r); }
  void bge(Register r) { b(ge, r); }
  void b(Register r) { b(al, r); }
  void jmp(Register r) { b(al, r); }
  void bunordered(Register r) { b(unordered, r); }
  void bordered(Register r) { b(ordered, r); }

  // wrappers around asm instr
  void brxh(Register dst, Register inc, Label* L) {
    int offset_halfwords = branch_offset(L) / 2;
    CHECK(is_int16(offset_halfwords));
    brxh(dst, inc, Operand(offset_halfwords));
  }

  void brxhg(Register dst, Register inc, Label* L) {
    int offset_halfwords = branch_offset(L) / 2;
    CHECK(is_int16(offset_halfwords));
    brxhg(dst, inc, Operand(offset_halfwords));
  }

  template <class R1, class R2>
  void ledbr(R1 r1, R2 r2) {
    ledbra(Condition(0), Condition(0), r1, r2);
  }

  template <class R1, class R2>
  void cdfbr(R1 r1, R2 r2) {
    cdfbra(Condition(0), Condition(0), r1, r2);
  }

  template <class R1, class R2>
  void cdgbr(R1 r1, R2 r2) {
    cdgbra(Condition(0), Condition(0), r1, r2);
  }

  template <class R1, class R2>
  void cegbr(R1 r1, R2 r2) {
    cegbra(Condition(0), Condition(0), r1, r2);
  }

  template <class R1, class R2>
  void cgebr(Condition m3, R1 r1, R2 r2) {
    cgebra(m3, Condition(0), r1, r2);
  }

  template <class R1, class R2>
  void cgdbr(Condition m3, R1 r1, R2 r2) {
    cgdbra(m3, Condition(0), r1, r2);
  }

  template <class R1, class R2>
  void cfdbr(Condition m3, R1 r1, R2 r2) {
    cfdbra(m3, Condition(0), r1, r2);
  }

  template <class R1, class R2>
  void cfebr(Condition m3, R1 r1, R2 r2) {
    cfebra(m3, Condition(0), r1, r2);
  }

  // ---------------------------------------------------------------------------
  // InstructionStream generation

  // Insert the smallest number of nop instructions
  // possible to align the pc offset to a multiple
  // of m. m must be a power of 2 (>= 4).
  void Align(int m);
  // Insert the smallest number of zero bytes possible to align the pc offset
  // to a mulitple of m. m must be a power of 2 (>= 2).
  void DataAlign(int m);
  // Aligns code to something that's optimal for a jump target for the platform.
  void CodeTargetAlign();
  void LoopHeaderAlign() { CodeTargetAlign(); }

  void breakpoint(bool do_print) {
    if (do_print) {
      PrintF("DebugBreak is inserted to %p\n", static_cast<void*>(pc_));
    }
#if V8_HOST_ARCH_64_BIT
    int64_t value = reinterpret_cast<uint64_t>(&v8::base::OS::DebugBreak);
    int32_t hi_32 = static_cast<int64_t>(value) >> 32;
    int32_t lo_32 = static_cast<int32_t>(value);

    iihf(r1, Operand(hi_32));
    iilf(r1, Operand(lo_32));
#else
    iilf(r1, Operand(reinterpret_cast<uint32_t>(&v8::base::OS::DebugBreak)));
#endif
    basr(r14, r1);
  }

  void call(Handle<Code> target, RelocInfo::Mode rmode);
  void jump(Handle<Code> target, RelocInfo::Mode rmode, Condition cond);

// S390 instruction generation
#define DECLARE_VRR_A_INSTRUCTIONS(name, opcode_name, opcode_value)           \
  void name(DoubleRegister v1, DoubleRegister v2, Condition m5, Condition m4, \
            Condition m3) {                                                   \
    uint64_t code = (static_cast<uint64_t>(opcode_value & 0xFF00)) * B32 |    \
                    (static_cast<uint64_t>(v1.code())) * B36 |                \
                    (static_cast<uint64_t>(v2.code())) * B32 |                \
                    (static_cast<uint64_t>(m5 & 0xF)) * B20 |                 \
                    (static_cast<uint64_t>(m4 & 0xF)) * B16 |                 \
                    (static_cast<uint64_t>(m3 & 0xF)) * B12 |                 \
                    (static_cast<uint64_t>(0)) * B8 |                         \
                    (static_cast<uint64_t>(opcode_value & 0x00FF));           \
    emit6bytes(code);                                                         \
  }
  S390_VRR_A_OPCODE_LIST(DECLARE_VRR_A_INSTRUCTIONS)
#undef DECLARE_VRR_A_INSTRUCTIONS

#define DECLARE_VRR_C_INSTRUCTIONS(name, opcode_name, opcode_value)        \
  void name(DoubleRegister v1, DoubleRegister v2, DoubleRegister v3,       \
            Condition m6, Condition m5, Condition m4) {                    \
    uint64_t code = (static_cast<uint64_t>(opcode_value & 0xFF00)) * B32 | \
                    (static_cast<uint64_t>(v1.code())) * B36 |             \
                    (static_cast<uint64_t>(v2.code())) * B32 |             \
                    (static_cast<uint64_t>(v3.code())) * B28 |             \
                    (static_cast<uint64_t>(m6 & 0xF)) * B20 |              \
                    (static_cast<uint64_t>(m5 & 0xF)) * B16 |              \
                    (static_cast<uint64_t>(m4 & 0xF)) * B12 |              \
                    (static_cast<uint64_t>(0)) * B8 |                      \
                    (static_cast<uint64_t>(opcode_value & 0x00FF));        \
    emit6bytes(code);                                                      \
  }
  S390_VRR_C_OPCODE_LIST(DECLARE_VRR_C_INSTRUCTIONS)
#undef DECLARE_VRR_C_INSTRUCTIONS

#define DECLARE_VRR_B_INSTRUCTIONS(name, opcode_name, opcode_value)        \
  void name(DoubleRegister v1, DoubleRegister v2, DoubleRegister v3,       \
            Condition m5, Condition m4) {                                  \
    uint64_t code = (static_cast<uint64_t>(opcode_value & 0xFF00)) * B32 | \
                    (static_cast<uint64_t>(v1.code())) * B36 |             \
                    (static_cast<uint64_t>(v2.code())) * B32 |             \
                    (static_cast<uint64_t>(v3.code())) * B28 |             \
                    (static_cast<uint64_t>(m5 & 0xF)) * B20 |              \
                    (static_cast<uint64_t>(m4 & 0xF)) * B12 |              \
                    (static_cast<uint64_t>(0)) * B8 |                      \
                    (static_cast<uint64_t>(opcode_value & 0x00FF));        \
    emit6bytes(code);                                                      \
  }
  S390_VRR_B_OPCODE_LIST(DECLARE_VRR_B_INSTRUCTIONS)
#undef DECLARE_VRR_B_INSTRUCTIONS

#define DECLARE_VRR_E_INSTRUCTIONS(name, opcode_name, opcode_value)        \
  void name(DoubleRegister v1, DoubleRegister v2, DoubleRegister v3,       \
            DoubleRegister v4, Condition m6, Condition m5) {               \
    uint64_t code = (static_cast<uint64_t>(opcode_value & 0xFF00)) * B32 | \
                    (static_cast<uint64_t>(v1.code())) * B36 |             \
                    (static_cast<uint64_t>(v2.code())) * B32 |             \
                    (static_cast<uint64_t>(v3.code())) * B28 |             \
                    (static_cast<uint64_t>(m6 & 0xF)) * B24 |              \
                    (static_cast<uint64_t>(m5 & 0xF)) * B16 |              \
                    (static_cast<uint64_t>(v4.code())) * B12 |             \
                    (static_cast<uint64_t>(0)) * B8 |                      \
                    (static_cast<uint64_t>(opcode_value & 0x00FF));        \
    emit6bytes(code);                                                      \
  }
  S390_VRR_E_OPCODE_LIST(DECLARE_VRR_E_INSTRUCTIONS)
#undef DECLARE_VRR_E_INSTRUCTIONS

#define DECLARE_VRR_F_INSTRUCTIONS(name, opcode_name, opcode_value)        \
  void name(DoubleRegister v1, Register r1, Register r2) {                 \
    uint64_t code = (static_cast<uint64_t>(opcode_value & 0xFF00)) * B32 | \
                    (static_cast<uint64_t>(v1.code())) * B36 |             \
                    (static_cast<uint64_t>(r1.code())) * B32 |             \
                    (static_cast<uint64_t>(r2.code())) * B28 |             \
                    (static_cast<uint64_t>(0)) * B8 |                      \
                    (static_cast<uint64_t>(opcode_value & 0x00FF));        \
    emit6bytes(code);                                                      \
  }
  S390_VRR_F_OPCODE_LIST(DECLARE_VRR_F_INSTRUCTIONS)
#undef DECLARE_VRR_E_INSTRUCTIONS

#define DECLARE_VRX_INSTRUCTIONS(name, opcode_name, opcode_value)       \
  void name(DoubleRegister v1, const MemOperand& opnd, Condition m3) {  \
    uint64_t code =                                                     \
        (static_cast<uint64_t>(opcode_value & 0xFF00)) * B32 |          \
        (static_cast<uint64_t>(v1.code())) * B36 |                      \
        (static_cast<uint64_t>(opnd.getIndexRegister().code())) * B32 | \
        (static_cast<uint64_t>(opnd.getBaseRegister().code())) * B28 |  \
        (static_cast<uint64_t>(opnd.getDisplacement())) * B16 |         \
        (static_cast<uint64_t>(m3 & 0xF)) * B12 |                       \
        (static_cast<uint64_t>(0)) * B8 |                               \
        (static_cast<uint64_t>(opcode_value & 0x00FF));                 \
    emit6bytes(code);                                                   \
  }
  S390_VRX_OPCODE_LIST(DECLARE_VRX_INSTRUCTIONS)
#undef DECLARE_VRX_INSTRUCTIONS

#define DECLARE_VRS_A_INSTRUCTIONS(name, opcode_name, opcode_value)       \
  void name(DoubleRegister v1, DoubleRegister v2, const MemOperand& opnd, \
            Condition m4 = Condition(0)) {                                \
    uint64_t code =                                                       \
        (static_cast<uint64_t>(opcode_value & 0xFF00)) * B32 |            \
        (static_cast<uint64_t>(v1.code())) * B36 |                        \
        (static_cast<uint64_t>(v2.code())) * B32 |                        \
        (static_cast<uint64_t>(opnd.getBaseRegister().code())) * B28 |    \
        (static_cast<uint64_t>(opnd.getDisplacement())) * B16 |           \
        (static_cast<uint64_t>(m4 & 0xF)) * B12 |                         \
        (static_cast<uint64_t>(0)) * B8 |                                 \
        (static_cast<uint64_t>(opcode_value & 0x00FF));                   \
    emit6bytes(code);                                                     \
  }
  S390_VRS_A_OPCODE_LIST(DECLARE_VRS_A_INSTRUCTIONS)
#undef DECLARE_VRS_A_INSTRUCTIONS

#define DECLARE_VRS_B_INSTRUCTIONS(name, opcode_name, opcode_value)    \
  void name(DoubleRegister v1, Register r1, const MemOperand& opnd,    \
            Condition m4 = Condition(0)) {                             \
    uint64_t code =                                                    \
        (static_cast<uint64_t>(opcode_value & 0xFF00)) * B32 |         \
        (static_cast<uint64_t>(v1.code())) * B36 |                     \
        (static_cast<uint64_t>(r1.code())) * B32 |                     \
        (static_cast<uint64_t>(opnd.getBaseRegister().code())) * B28 | \
        (static_cast<uint64_t>(opnd.getDisplacement())) * B16 |        \
        (static_cast<uint64_t>(m4 & 0xF)) * B12 |                      \
        (static_cast<uint64_t>(0)) * B8 |                              \
        (static_cast<uint64_t>(opcode_value & 0x00FF));                \
    emit6bytes(code);                                                  \
  }
  S390_VRS_B_OPCODE_LIST(DECLARE_VRS_B_INSTRUCTIONS)
#undef DECLARE_VRS_B_INSTRUCTIONS

#define DECLARE_VRS_C_INSTRUCTIONS(name, opcode_name, opcode_value)    \
  void name(Register r1, DoubleRegister v1, const MemOperand& opnd,    \
            Condition m4 = Condition(0)) {                             \
    uint64_t code =                                                    \
        (static_cast<uint64_t>(opcode_value & 0xFF00)) * B32 |         \
        (static_cast<uint64_t>(r1.code())) * B36 |                     \
        (static_cast<uint64_t>(v1.code())) * B32 |                     \
        (static_cast<uint64_t>(opnd.getBaseRegister().code())) * B28 | \
        (static_cast<uint64_t>(opnd.getDisplacement())) * B16 |        \
        (static_cast<uint64_t>(m4 & 0xF)) * B12 |                      \
        (static_cast<uint64_t>(0)) * B8 |                              \
        (static_cast<uint64_t>(opcode_value & 0x00FF));                \
    emit6bytes(code);                                                  \
  }
  S390_VRS_C_OPCODE_LIST(DECLARE_VRS_C_INSTRUCTIONS)
#undef DECLARE_VRS_C_INSTRUCTIONS

#define DECLARE_VRI_A_INSTRUCTIONS(name, opcode_name, opcode_value)        \
  void name(DoubleRegister v1, const Operand& i2, Condition m3) {          \
    uint64_t code = (static_cast<uint64_t>(opcode_value & 0xFF00)) * B32 | \
                    (static_cast<uint64_t>(v1.code())) * B36 |             \
                    (static_cast<uint32_t>(i2.immediate())) * B16 |        \
                    (static_cast<uint64_t>(m3 & 0xF)) * B12 |              \
                    (static_cast<uint64_t>(0)) * B8 |                      \
                    (static_cast<uint64_t>(opcode_value & 0x00FF));        \
    emit6bytes(code);                                                      \
  }
  S390_VRI_A_OPCODE_LIST(DECLARE_VRI_A_INSTRUCTIONS)
#undef DECLARE_VRI_A_INSTRUCTIONS

#define DECLARE_VRI_C_INSTRUCTIONS(name, opcode_name, opcode_value)        \
  void name(DoubleRegister v1, DoubleRegister v2, const Operand& i2,       \
            Condition m4) {                                                \
    uint64_t code = (static_cast<uint64_t>(opcode_value & 0xFF00)) * B32 | \
                    (static_cast<uint64_t>(v1.code())) * B36 |             \
                    (static_cast<uint64_t>(v2.code())) * B32 |             \
                    (static_cast<uint16_t>(i2.immediate())) * B16 |        \
                    (static_cast<uint64_t>(m4 & 0xF)) * B12 |              \
                    (static_cast<uint64_t>(0)) * B8 |                      \
                    (static_cast<uint64_t>(opcode_value & 0x00FF));        \
    emit6bytes(code);                                                      \
  }
  S390_VRI_C_OPCODE_LIST(DECLARE_VRI_C_INSTRUCTIONS)
#undef DECLARE_VRI_C_INSTRUCTIONS

  // Single Element format
  void vfa(DoubleRegister v1, DoubleRegister v2, DoubleRegister v3) {
    vfa(v1, v2, v3, static_cast<Condition>(0), static_cast<Condition>(8),
        static_cast<Condition>(3));
  }
  void vfs(DoubleRegister v1, DoubleRegister v2, DoubleRegister v3) {
    vfs(v1, v2, v3, static_cast<Condition>(0), static_cast<Condition>(8),
        static_cast<Condition>(3));
  }
  void vfm(DoubleRegister v1, DoubleRegister v2, DoubleRegister v3) {
    vfm(v1, v2, v3, static_cast<Condition>(0), static_cast<Condition>(8),
        static_cast<Condition>(3));
  }
  void vfd(DoubleRegister v1, DoubleRegister v2, DoubleRegister v3) {
    vfd(v1, v2, v3, static_cast<Condition>(0), static_cast<Condition>(8),
        static_cast<Condition>(3));
  }

  // Load Address Instructions
  void larl(Register r, Label* l);
  void lgrl(Register r, Label* l);

  // Exception-generating instructions and debugging support
  void stop(Condition cond = al, int32_t code = kDefaultStopCode,
            CRegister cr = cr7);

  void bkpt(uint32_t imm16);  // v5 and above

  // Different nop operations are used by the code generator to detect certain
  // states of the generated code.
  enum NopMarkerTypes {
    NON_MARKING_NOP = 0,
    GROUP_ENDING_NOP,
    DEBUG_BREAK_NOP,
#if V8_OS_ZOS
    BASR_CALL_TYPE_NOP,
    BRAS_CALL_TYPE_NOP,
    BRASL_CALL_TYPE_NOP,
#endif
    // IC markers.
    PROPERTY_ACCESS_INLINED,
    PROPERTY_ACCESS_INLINED_CONTEXT,
    PROPERTY_ACCESS_INLINED_CONTEXT_DONT_DELETE,
    // Helper values.
    LAST_CODE_MARKER,
    FIRST_IC_MARKER = PROPERTY_ACCESS_INLINED
  };

  void nop(int type = 0);  // 0 is the default non-marking type.

  void dumy(int r1, int x2, int b2, int d2);

  // Check the code size generated from label to here.
  int SizeOfCodeGeneratedSince(Label* label) {
    return pc_offset() - label->pos();
  }

  // Record a deoptimization reason that can be used by a log or cpu profiler.
  // Use --trace-deopt to enable.
  void RecordDeoptReason(DeoptimizeReason reason, uint32_t node_id,
                         SourcePosition position, int id);

  // Writes a single byte or word of data in the code stream.  Used
  // for inline tables, e.g., jump-tables.
  void db(uint8_t data);
  void dh(uint16_t data);
  void dd(uint32_t data);
  void dq(uint64_t data);
  void dp(uintptr_t data);

  // Read/patch instructions
  SixByteInstr instr_at(int pos) {
    return Instruction::InstructionBits(buffer_start_ + pos);
  }
  template <typename T>
  void instr_at_put(int pos, T instr) {
    Instruction::SetInstructionBits<T>(buffer_start_ + pos, instr);
  }

  // Decodes instruction at pos, and returns its length
  int32_t instr_length_at(int pos) {
    return Instruction::InstructionLength(buffer_start_ + pos);
  }

  static SixByteInstr instr_at(uint8_t* pc) {
    return Instruction::InstructionBits(pc);
  }

  static Condition GetCondition(Instr instr);

  static bool IsBranch(Instr instr);
  static bool Is64BitLoadIntoIP(SixByteInstr instr1, SixByteInstr instr2);

  static bool IsCmpRegister(Instr instr);
  static bool IsCmpImmediate(Instr instr);
  static bool IsNop(SixByteInstr instr, int type = NON_MARKING_NOP);

  // The code currently calls CheckBuffer() too often. This has the side
  // effect of randomly growing the buffer in the middle of multi-instruction
  // sequences.
  //
  // This function allows outside callers to check and grow the buffer
  void EnsureSpaceFor(int space_needed);

  void EmitRelocations();
  void emit_label_addr(Label* label);

 public:
  uint8_t* buffer_pos() const { return buffer_start_; }

  // InstructionStream generation
  // The relocation writer's position is at least kGap bytes below the end of
  // the generated instructions. This is so that multi-instruction sequences do
  // not have to check for overflow. The same is true for writes of large
  // relocation info entries.
  static constexpr int kGap = 32;
  static_assert(AssemblerBase::kMinimalBufferSize >= 2 * kGap);

 protected:
  int buffer_space() const { return reloc_info_writer.pos() - pc_; }

  // Decode instruction(s) at pos and return backchain to previous
  // label reference or kEndOfChain.
  int target_at(int pos);

  // Patch instruction(s) at pos to target target_pos (e.g. branch)
  void target_at_put(int pos, int target_pos, bool* is_branch = nullptr);

  // Record reloc info for current pc_
  void RecordRelocInfo(RelocInfo::Mode rmode, intptr_t data = 0);

 private:
  // Avoid overflows for displacements etc.
  static const int kMaximalBufferSize = 512 * MB;

  // Relocation info generation
  // Each relocation is encoded as a variable size value
  static constexpr int kMaxRelocSize = RelocInfoWriter::kMaxSize;
  RelocInfoWriter reloc_info_writer;
  std::vector<DeferredRelocInfo> relocations_;

  // Scratch registers available for use by the Assembler.
  RegList scratch_register_list_;
  DoubleRegList scratch_double_register_list_;

  // The bound position, before this we cannot do instruction elimination.
  int last_bound_pos_;

  // Code emission
  void CheckBuffer() {
    if (buffer_space() <= kGap) {
      GrowBuffer();
    }
  }
  void GrowBuffer(int needed = 0);
  inline void TrackBranch();
  inline void UntrackBranch();

  // Helper to emit the binary encoding of a 2 byte instruction
  void emit2bytes(uint16_t x) {
    CheckBuffer();
#if V8_TARGET_LITTLE_ENDIAN
    // We need to emit instructions in big endian format as disassembler /
    // simulator require the first byte of the instruction in order to decode
    // the instruction length.  Swap the bytes.
    x = ((x & 0x00FF) << 8) | ((x & 0xFF00) >> 8);
#endif
    *reinterpret_cast<uint16_t*>(pc_) = x;
    pc_ += 2;
  }

  // Helper to emit the binary encoding of a 4 byte instruction
  void emit4bytes(uint32_t x) {
    CheckBuffer();
#if V8_TARGET_LITTLE_ENDIAN
    // We need to emit instructions in big endian format as disassembler /
    // simulator require the first byte of the instruction in order to decode
    // the instruction length.  Swap the bytes.
    x = ((x & 0x000000FF) << 24) | ((x & 0x0000FF00) << 8) |
        ((x & 0x00FF0000) >> 8) | ((x & 0xFF000000) >> 24);
#endif
    *reinterpret_cast<uint32_t*>(pc_) = x;
    pc_ += 4;
  }

  // Helper to emit the binary encoding of a 6 byte instruction
  void emit6bytes(uint64_t x) {
    CheckBuffer();
#if V8_TARGET_LITTLE_ENDIAN
    // We need to emit instructions in big endian format as disassembler /
    // simulator require the first byte of the instruction in order to decode
    // the instruction length.  Swap the bytes.
    x = (static_cast<uint64_t>(x & 0xFF) << 40) |
        (static_cast<uint64_t>((x >> 8) & 0xFF) << 32) |
        (static_cast<uint64_t>((x >> 16) & 0xFF) << 24) |
        (static_cast<uint64_t>((x >> 24) & 0xFF) << 16) |
        (static_cast<uint64_t>((x >> 32) & 0xFF) << 8) |
        (static_cast<uint64_t>((x >> 40) & 0xFF));
    x |= (*reinterpret_cast<uint64_t*>(pc_) >> 48) << 48;
#else
    // We need to pad two bytes of zeros in order to get the 6-bytes
    // stored from low address.
    x = x << 16;
    x |= *reinterpret_cast<uint64_t*>(pc_) & 0xFFFF;
#endif
    // It is safe to store 8-bytes, as CheckBuffer() guarantees we have kGap
    // space left over.
    *reinterpret_cast<uint64_t*>(pc_) = x;
    pc_ += 6;
  }

  // Labels
  void print(Label* L);
  int max_reach_from(int pos);
  void bind_to(Label* L, int pos);
  void next(Label* L);

  void AllocateAndInstallRequestedHeapNumbers(LocalIsolate* isolate);

  int WriteCodeComments();

  friend class RegExpMacroAssemblerS390;
  friend class RelocInfo;
  friend class EnsureSpace;
  friend class UseScratchRegisterScope;
};

class EnsureSpace {
 public:
  explicit EnsureSpace(Assembler* assembler) { assembler->CheckBuffer(); }
};

class V8_EXPORT_PRIVATE V8_NODISCARD UseScratchRegisterScope {
 public:
  explicit UseScratchRegisterScope(Assembler* assembler)
      : assembler_(assembler),
        old_available_(*assembler->GetScratchRegisterList()),
        old_available_double_(*assembler->GetScratchDoubleRegisterList()) {}

  ~UseScratchRegisterScope() {
    *assembler_->GetScratchRegisterList() = old_available_;
    *assembler_->GetScratchD
```