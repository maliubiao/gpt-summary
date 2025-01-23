Response:
Let's break down the thought process for analyzing this code snippet and fulfilling the request.

1. **Understand the Context:** The initial prompt clearly states this is a C++ source file (`.cc`) for the V8 JavaScript engine, specifically for the s390 architecture's simulator. The simulator's purpose is to emulate the behavior of an s390 processor.

2. **Identify the Core Functionality:** The code is filled with `EVALUATE(INSTRUCTION_NAME)` blocks. This immediately suggests that the primary function of this file is to implement the execution logic for various s390 assembly instructions within the simulator. Each `EVALUATE` block likely corresponds to a specific s390 instruction.

3. **Examine Individual Instruction Implementations:**  Start looking at the structure within the `EVALUATE` blocks. Notice common patterns:
    * `DCHECK_OPCODE(INSTRUCTION_NAME)`:  A debugging check to ensure the correct instruction is being handled.
    * `DECODE_*_INSTRUCTION(...)`:  Macros used to extract operands (registers, immediate values, memory addresses) from the instruction's binary representation. The different `DECODE_*` variations indicate different instruction formats.
    * `get_register(...)`, `get_low_register(...)`, `set_register(...)`, `set_low_register(...)`: Functions to access and modify the simulated CPU registers.
    * `ReadB(...)`, `ReadW(...)`, `ReadDW(...)`, `WriteB(...)`, `WriteW(...)`, `WriteDW(...)`: Functions to simulate memory access (read and write bytes, words, double words).
    * Arithmetic and logical operations are performed on the extracted operands.
    * `condition_reg_ = ...`, `SetS390ConditionCode(...)`, `SetS390OverflowCode(...)`:  Code related to updating the simulated CPU's condition codes and overflow flags.
    * `set_pc(...)`:  Modifies the simulated program counter, used for branching and jumps.
    * `__atomic_compare_exchange_n(...)`, `__atomic_fetch_and(...)`, etc.:  Atomic operations for simulating concurrent memory access.
    * `UNIMPLEMENTED()`:  Indicates that the particular instruction is not yet implemented in the simulator.

4. **Categorize Instruction Types:** As you go through the `EVALUATE` blocks, you can start to categorize the types of instructions being simulated:
    * Data movement (loads, stores: `STMG`, `STMH`, `STMY`, `LMY`, `LEY`, `LDY`, `STEY`, `STDY`)
    * Arithmetic and logical operations (add, subtract, shift, rotate, compare: `SLLG`, `SRLG`, `RLLG`, `ASI`, `AGSI`, `SRAK`, `SLAK`, `SRLK`, `SLLK`)
    * Control flow (branches: `BRXHG`)
    * Atomic operations (compare-and-swap, fetch-and-op: `CS`, `CSY`, `CSG`, `LANG`, `LAOG`, `LAXG`, `LAAG`, `LAN`, `LAO`, `LAX`, `LAA`)
    * Floating-point operations (`LDEB`, `CEB`, `AEB`, `SEB`, `DEB`, `MEEB`, `CDB`, `ADB`, `SDB`, `MDB`, `DDB`, `SQDB`)
    * Bit manipulation (`TM`, `TMY`)

5. **Address the Specific Requirements of the Prompt:**

    * **Functionality Listing:**  Based on the instruction categorization, list the main functionalities.
    * **Torque:**  The code ends with `.cc`, so it's C++, not Torque.
    * **Relationship to JavaScript:**  Explain that this code simulates the *underlying* architecture on which JavaScript *might* run. Give a conceptual example of a JavaScript operation and how it might eventually translate to these low-level instructions. *Initially, I might think too directly about JavaScript syntax. I need to step back and think about the abstract operations.*
    * **JavaScript Example:** Provide a simple JavaScript example that illustrates a concept that the simulated instructions handle (e.g., addition, variable assignment which involves load/store).
    * **Code Logic Inference (Hypothetical Input/Output):**  Choose a simple instruction like `SLLG` (Shift Left Logical) and create a scenario with register values and the expected result after the instruction executes.
    * **Common Programming Errors:** Think about errors related to memory access (like incorrect addresses, alignment issues) or assumptions about atomic operations that could go wrong in a real programming scenario. *It's important to link these errors back to the types of operations the simulator handles.*
    * **Part 10 of 10 - Summarization:**  Emphasize that this is the final part and reiterate the core purpose: simulating s390 instructions for the V8 engine.

6. **Refine and Organize:** Structure the answer clearly with headings for each of the prompt's requirements. Use concise language and avoid overly technical jargon where possible. Double-check the generated JavaScript example and the hypothetical input/output for correctness.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focusing too much on the specific syntax of each instruction.
* **Correction:** Shift focus to the *general function* each instruction performs (data movement, arithmetic, control flow).
* **Initial thought:**  Trying to find a direct, one-to-one mapping between JavaScript and these instructions.
* **Correction:** Realize that the mapping is complex and involves many layers. The JavaScript example should illustrate a high-level concept that *could* involve these instructions at a much lower level.
* **Initial thought:**  Overcomplicating the hypothetical input/output.
* **Correction:** Choose a straightforward instruction and simple input values to clearly demonstrate the effect.
* **Initial thought:** Listing every single instruction as a separate function.
* **Correction:** Group instructions by category for a more concise summary of functionalities.

By following these steps and iterating on the analysis, we can arrive at a comprehensive and accurate answer that addresses all aspects of the prompt.
好的，让我们来分析一下 `v8/src/execution/s390/simulator-s390.cc` 这个文件的功能。

**文件功能概述**

`v8/src/execution/s390/simulator-s390.cc` 是 V8 JavaScript 引擎中用于模拟 IBM System z (s390) 架构处理器指令集的一个 C++ 源文件。它的主要功能是：

1. **指令解码和执行:**  它包含了大量 `EVALUATE(INSTRUCTION_NAME)` 宏定义的代码块，每个代码块对应一个特定的 s390 汇编指令。这些代码块负责：
   - **解码指令:** 从指令的二进制表示中提取操作码和操作数（寄存器、立即数、内存地址等）。
   - **模拟指令行为:**  根据 s390 架构规范，模拟该指令在处理器上的行为，包括：
     - 读取和写入模拟的 CPU 寄存器 (`get_register`, `set_register`, `get_low_register`, `set_low_register`)。
     - 读取和写入模拟的内存 (`ReadB`, `ReadW`, `ReadDW`, `WriteB`, `WriteW`, `WriteDW`)。
     - 执行算术和逻辑运算。
     - 更新条件码寄存器 (`condition_reg_`, `SetS390ConditionCode`, `SetS390OverflowCode`)。
     - 修改模拟的程序计数器 (`set_pc`)，用于控制程序流程。
     - 执行原子操作 (`__atomic_compare_exchange_n`, `__atomic_fetch_and` 等)。
     - 执行浮点运算（处理浮点寄存器 `fpr`）。

2. **支持 V8 的执行:** 这个模拟器使得 V8 能够在非 s390 架构的机器上运行和测试为 s390 架构编译的代码。这对于开发、调试和测试 V8 在 s390 平台上的功能至关重要。

**关于文件扩展名和 Torque**

你提到如果文件以 `.tq` 结尾，那它就是一个 V8 Torque 源代码文件。 `v8/src/execution/s390/simulator-s390.cc` 以 `.cc` 结尾，所以它是一个 **C++ 源代码文件**，而不是 Torque 文件。Torque 是一种 V8 自定义的领域特定语言，用于定义 V8 的内置函数和运行时代码。

**与 JavaScript 功能的关系及示例**

虽然这个 C++ 文件本身不是直接用 JavaScript 编写的，但它直接关系到 JavaScript 代码在 s390 架构上的执行。当 V8 引擎在 s390 平台上执行 JavaScript 代码时，它会将 JavaScript 代码编译成 s390 的机器码。这个模拟器允许在非 s390 平台上 *模拟* 执行这些机器码。

例如，一个简单的 JavaScript 加法操作：

```javascript
let a = 5;
let b = 10;
let sum = a + b;
```

在 s390 架构上，V8 可能会将 `a + b` 编译成类似以下的 s390 汇编指令序列（简化表示）：

```assembly
L  %r1, [address_of_a]  ; 将变量 a 的值加载到寄存器 r1
L  %r2, [address_of_b]  ; 将变量 b 的值加载到寄存器 r2
AR %r1, %r2           ; 将寄存器 r2 的值加到寄存器 r1
ST %r1, [address_of_sum] ; 将寄存器 r1 的结果存储到变量 sum 的地址
```

`v8/src/execution/s390/simulator-s390.cc` 文件中的 `EVALUATE` 宏可能会包含类似以下的代码来模拟 `AR` (Add Register) 指令：

```c++
EVALUATE(AR) {
  DCHECK_OPCODE(AR);
  DECODE_RR_INSTRUCTION(r1, r2); // 假设有这样一个解码宏
  int64_t r1_val = get_register(r1);
  int64_t r2_val = get_register(r2);
  int64_t alu_out = r1_val + r2_val;
  set_register(r1, alu_out);
  // ... 更新条件码等
  return length;
}
```

**代码逻辑推理及假设输入输出**

让我们以 `SLLG` (Shift Left Logical, General) 指令为例进行推理。

**假设输入:**

- 寄存器 `r3` 的值为 `0x0000000012345678`
- 寄存器 `b2` 的值为 `0`
- 位移量 `d2` 的值为 `4`
- 执行的指令是 `SLLG r1, r3, D(b2)`，其中 `D(b2)` 计算出的位移量为 `b2 + d2 = 0 + 4 = 4`。

**对应的 `EVALUATE(SLLG)` 代码片段 (来自你提供的代码):**

```c++
EVALUATE(SLLG) {
  DCHECK_OPCODE(SLLG);
  // For SLLG/SRLG, the 64-bit third operand is shifted the number
  // of bits specified by the second-operand address, and the result is
  // placed at the first-operand location. Except for when the R1 and R3
  // fields designate the same register, the third operand remains
  // unchanged in general register R3.
  DECODE_RSY_A_INSTRUCTION(r1, r3, b2, d2);
  // only takes rightmost 6 bits
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int shiftBits = (b2_val + d2) & 0x3F;
  uint64_t r3_val = get_register(r3);
  uint64_t alu_out = r3_val << shiftBits;
  set_register(r1, alu_out);
  return length;
}
```

**推理过程:**

1. `DECODE_RSY_A_INSTRUCTION(r1, r3, b2, d2)` 会解析出操作数：目标寄存器 `r1`，源寄存器 `r3`，基址寄存器 `b2`，偏移量 `d2`。
2. `int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);` 由于 `b2` 为 0，`b2_val` 为 0。
3. `int shiftBits = (b2_val + d2) & 0x3F;` 计算位移量：`(0 + 4) & 0x3F = 4`。
4. `uint64_t r3_val = get_register(r3);` 获取 `r3` 的值： `0x0000000012345678`。
5. `uint64_t alu_out = r3_val << shiftBits;` 执行左移操作： `0x0000000012345678 << 4 = 0x0000000123456780`。
6. `set_register(r1, alu_out);` 将结果 `0x0000000123456780` 写入目标寄存器 `r1`。

**预期输出:**

- 寄存器 `r1` 的值变为 `0x0000000123456780`。
- 寄存器 `r3` 的值保持不变（`0x0000000012345678`）。

**用户常见的编程错误示例**

在与这类底层代码交互时，用户常犯的编程错误可能包括：

1. **内存地址错误:**
   - **未对齐的内存访问:** 某些指令要求访问特定大小的数据类型时，内存地址必须是该数据类型大小的倍数。例如，读取一个 4 字节的整数，地址必须是 4 的倍数。如果传递了错误的地址，模拟器或实际硬件可能会崩溃或产生不可预测的结果。

   ```c++
   // 假设要读取一个 4 字节的整数
   intptr_t bad_addr = 0x1001; // 奇数地址
   // ...
   // 模拟读取操作，会导致错误
   // uint32_t value = ReadW(bad_addr);
   ```

2. **寄存器使用错误:**
   - **使用错误的寄存器编号:**  指令的操作数指定了寄存器编号，如果使用了不存在或含义不同的寄存器，会导致错误。
   - **假设寄存器的初始值:**  在没有明确初始化的情况下使用寄存器，其值可能是未定义的，导致程序行为不可预测。

3. **位运算错误:**
   - **位移量超出范围:** 移位指令的位移量通常有最大值限制（例如，对于 64 位寄存器，通常是 0-63）。超出范围的位移量可能导致意想不到的结果。

   ```c++
   int64_t value = 0x1;
   int shift = 64; // 对于 64 位移位来说过大
   // ...
   // 模拟左移，结果可能不是预期的
   // uint64_t shifted_value = value << shift;
   ```

4. **原子操作的误用:**
   - **不理解原子性保证:**  原子操作旨在提供并发环境下的数据一致性。如果使用不当或对原子性的理解有误，仍然可能出现竞态条件。
   - **错误的内存屏障使用:**  原子操作通常与内存屏障结合使用，以确保操作的顺序性对其他线程可见。缺乏正确的内存屏障可能导致数据不一致。

**总结其功能 (第 10 部分，共 10 部分)**

作为系列的一部分，`v8/src/execution/s390/simulator-s390.cc` 文件是 V8 引擎中 **s390 架构模拟器的核心组成部分**。它的主要功能是 **逐条指令地模拟 s390 处理器的行为**，使得 V8 能够在非 s390 平台上运行和测试 s390 代码。这个模拟器对于 V8 在 s390 平台上的开发、调试和正确性至关重要，它通过 C++ 代码精确地复现了各种 s390 汇编指令的功能，包括数据操作、算术运算、控制流、原子操作和浮点运算等。

希望以上分析能够帮助你理解这个文件的功能！

### 提示词
```
这是目录为v8/src/execution/s390/simulator-s390.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/s390/simulator-s390.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第10部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
al << shiftBits;
  set_register(r1, alu_out);
  return length;
}

EVALUATE(CS) {
  DCHECK_OPCODE(CS);
  DECODE_RS_A_INSTRUCTION(r1, r3, rb, d2);
  int32_t offset = d2;
  int64_t rb_val = (rb == 0) ? 0 : get_register(rb);
  intptr_t target_addr = static_cast<intptr_t>(rb_val) + offset;

  int32_t r1_val = get_low_register<int32_t>(r1);
  int32_t r3_val = get_low_register<int32_t>(r3);

  DCHECK_EQ(target_addr & 0x3, 0);
  bool is_success = __atomic_compare_exchange_n(
      reinterpret_cast<int32_t*>(target_addr), &r1_val, r3_val, true,
      __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
  if (!is_success) {
    set_low_register(r1, r1_val);
    condition_reg_ = 0x4;
  } else {
    condition_reg_ = 0x8;
  }
  return length;
}

EVALUATE(CSY) {
  DCHECK_OPCODE(CSY);
  DECODE_RSY_A_INSTRUCTION(r1, r3, b2, d2);
  int32_t offset = d2;
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  intptr_t target_addr = static_cast<intptr_t>(b2_val) + offset;

  int32_t r1_val = get_low_register<int32_t>(r1);
  int32_t r3_val = get_low_register<int32_t>(r3);

  DCHECK_EQ(target_addr & 0x3, 0);
  bool is_success = __atomic_compare_exchange_n(
      reinterpret_cast<int32_t*>(target_addr), &r1_val, r3_val, true,
      __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
  if (!is_success) {
    set_low_register(r1, r1_val);
    condition_reg_ = 0x4;
  } else {
    condition_reg_ = 0x8;
  }
  return length;
}

EVALUATE(CSG) {
  DCHECK_OPCODE(CSG);
  DECODE_RSY_A_INSTRUCTION(r1, r3, b2, d2);
  int32_t offset = d2;
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  intptr_t target_addr = static_cast<intptr_t>(b2_val) + offset;

  int64_t r1_val = get_register(r1);
  int64_t r3_val = get_register(r3);

  DCHECK_EQ(target_addr & 0x3, 0);
  bool is_success = __atomic_compare_exchange_n(
      reinterpret_cast<int64_t*>(target_addr), &r1_val, r3_val, true,
      __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
  if (!is_success) {
    set_register(r1, r1_val);
    condition_reg_ = 0x4;
  } else {
    condition_reg_ = 0x8;
  }
  return length;
}

EVALUATE(RLLG) {
  DCHECK_OPCODE(RLLG);
  // For SLLG/SRLG, the 64-bit third operand is shifted the number
  // of bits specified by the second-operand address, and the result is
  // placed at the first-operand location. Except for when the R1 and R3
  // fields designate the same register, the third operand remains
  // unchanged in general register R3.
  DECODE_RSY_A_INSTRUCTION(r1, r3, b2, d2);
  // only takes rightmost 6 bits
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int shiftBits = (b2_val + d2) & 0x3F;
  // unsigned
  uint64_t r3_val = get_register(r3);
  uint64_t alu_out = 0;
  uint64_t rotateBits = r3_val >> (64 - shiftBits);
  alu_out = (r3_val << shiftBits) | (rotateBits);
  set_register(r1, alu_out);
  return length;
}

EVALUATE(STMG) {
  DCHECK_OPCODE(STMG);
  DECODE_RSY_A_INSTRUCTION(r1, r3, b2, d2);
  int rb = b2;
  int offset = d2;

  // Regs roll around if r3 is less than r1.
  // Artificially increase r3 by 16 so we can calculate
  // the number of regs stored properly.
  if (r3 < r1) r3 += 16;

  int64_t rb_val = (rb == 0) ? 0 : get_register(rb);

  // Store each register in ascending order.
  for (int i = 0; i <= r3 - r1; i++) {
    int64_t value = get_register((r1 + i) % 16);
    WriteDW(rb_val + offset + 8 * i, value);
  }
  return length;
}

EVALUATE(STMH) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(STCMH) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(STCMY) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CDSY) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CDSG) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(BXHG) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(BXLEG) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(ECAG) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(TM) {
  DCHECK_OPCODE(TM);
  // Test Under Mask (Mem - Imm) (8)
  DECODE_SI_INSTRUCTION_I_UINT8(b1, d1_val, imm_val)
  int64_t b1_val = (b1 == 0) ? 0 : get_register(b1);
  intptr_t addr = b1_val + d1_val;
  uint8_t mem_val = ReadB(addr);
  uint8_t selected_bits = mem_val & imm_val;
  // is TM
  bool is_tm_or_tmy = 1;
  condition_reg_ = TestUnderMask(selected_bits, imm_val, is_tm_or_tmy);
  return length;
}

EVALUATE(TMY) {
  DCHECK_OPCODE(TMY);
  // Test Under Mask (Mem - Imm) (8)
  DECODE_SIY_INSTRUCTION(b1, d1_val, imm_val);
  int64_t b1_val = (b1 == 0) ? 0 : get_register(b1);
  intptr_t addr = b1_val + d1_val;
  uint8_t mem_val = ReadB(addr);
  uint8_t selected_bits = mem_val & imm_val;
  // is TMY
  bool is_tm_or_tmy = 1;
  condition_reg_ = TestUnderMask(selected_bits, imm_val, is_tm_or_tmy);
  return length;
}

EVALUATE(MVIY) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(NIY) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CLIY) {
  DCHECK_OPCODE(CLIY);
  DECODE_SIY_INSTRUCTION(b1, d1, i2);
  // Compare Immediate (Mem - Imm) (8)
  int64_t b1_val = (b1 == 0) ? 0 : get_register(b1);
  intptr_t d1_val = d1;
  intptr_t addr = b1_val + d1_val;
  uint8_t mem_val = ReadB(addr);
  uint8_t imm_val = i2;
  SetS390ConditionCode<uint8_t>(mem_val, imm_val);
  return length;
}

EVALUATE(OIY) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(XIY) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(ASI) {
  DCHECK_OPCODE(ASI);
  // TODO(bcleung): Change all fooInstr->I2Value() to template functions.
  // The below static cast to 8 bit and then to 32 bit is necessary
  // because siyInstr->I2Value() returns a uint8_t, which a direct
  // cast to int32_t could incorrectly interpret.
  DECODE_SIY_INSTRUCTION(b1, d1, i2_unsigned);
  int8_t i2_8bit = static_cast<int8_t>(i2_unsigned);
  int32_t i2 = static_cast<int32_t>(i2_8bit);
  intptr_t b1_val = (b1 == 0) ? 0 : get_register(b1);

  int d1_val = d1;
  intptr_t addr = b1_val + d1_val;

  int32_t mem_val = ReadW(addr);
  bool isOF = CheckOverflowForIntAdd(mem_val, i2, int32_t);
  int32_t alu_out = mem_val + i2;
  SetS390ConditionCode<int32_t>(alu_out, 0);
  SetS390OverflowCode(isOF);
  WriteW(addr, alu_out);
  return length;
}

EVALUATE(ALSI) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(AGSI) {
  DCHECK_OPCODE(AGSI);
  // TODO(bcleung): Change all fooInstr->I2Value() to template functions.
  // The below static cast to 8 bit and then to 32 bit is necessary
  // because siyInstr->I2Value() returns a uint8_t, which a direct
  // cast to int32_t could incorrectly interpret.
  DECODE_SIY_INSTRUCTION(b1, d1, i2_unsigned);
  int8_t i2_8bit = static_cast<int8_t>(i2_unsigned);
  int64_t i2 = static_cast<int64_t>(i2_8bit);
  intptr_t b1_val = (b1 == 0) ? 0 : get_register(b1);

  int d1_val = d1;
  intptr_t addr = b1_val + d1_val;

  int64_t mem_val = ReadDW(addr);
  int isOF = CheckOverflowForIntAdd(mem_val, i2, int64_t);
  int64_t alu_out = mem_val + i2;
  SetS390ConditionCode<uint64_t>(alu_out, 0);
  SetS390OverflowCode(isOF);
  WriteDW(addr, alu_out);
  return length;
}

EVALUATE(ALGSI) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(ICMH) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(ICMY) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(MVCLU) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CLCLU) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(STMY) {
  DCHECK_OPCODE(STMY);
  DECODE_RSY_A_INSTRUCTION(r1, r3, b2, d2);
  // Load/Store Multiple (32)
  int offset = d2;

  // Regs roll around if r3 is less than r1.
  // Artificially increase r3 by 16 so we can calculate
  // the number of regs stored properly.
  if (r3 < r1) r3 += 16;

  int32_t b2_val = (b2 == 0) ? 0 : get_low_register<int32_t>(b2);

  // Store each register in ascending order.
  for (int i = 0; i <= r3 - r1; i++) {
    int32_t value = get_low_register<int32_t>((r1 + i) % 16);
    WriteW(b2_val + offset + 4 * i, value);
  }
  return length;
}

EVALUATE(LMH) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LMY) {
  DCHECK_OPCODE(LMY);
  DECODE_RSY_A_INSTRUCTION(r1, r3, b2, d2);
  // Load/Store Multiple (32)
  int offset = d2;

  // Regs roll around if r3 is less than r1.
  // Artificially increase r3 by 16 so we can calculate
  // the number of regs stored properly.
  if (r3 < r1) r3 += 16;

  int32_t b2_val = (b2 == 0) ? 0 : get_low_register<int32_t>(b2);

  // Store each register in ascending order.
  for (int i = 0; i <= r3 - r1; i++) {
    int32_t value = ReadW(b2_val + offset + 4 * i);
    set_low_register((r1 + i) % 16, value);
  }
  return length;
}

EVALUATE(TP) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SRAK) {
  DCHECK_OPCODE(SRAK);
  DECODE_RSY_A_INSTRUCTION(r1, r3, b2, d2);
  // 32-bit non-clobbering shift-left/right arithmetic
  // only takes rightmost 6 bits
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int shiftBits = (b2_val + d2) & 0x3F;
  int32_t r3_val = get_low_register<int32_t>(r3);
  int32_t alu_out = -1;
  bool isOF = false;
  if (shiftBits < 32) {
    alu_out = r3_val >> shiftBits;
  }
  set_low_register(r1, alu_out);
  SetS390ConditionCode<int32_t>(alu_out, 0);
  SetS390OverflowCode(isOF);
  return length;
}

EVALUATE(SLAK) {
  DCHECK_OPCODE(SLAK);
  DECODE_RSY_A_INSTRUCTION(r1, r3, b2, d2);
  // 32-bit non-clobbering shift-left/right arithmetic
  // only takes rightmost 6 bits
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int shiftBits = (b2_val + d2) & 0x3F;
  int32_t r3_val = get_low_register<int32_t>(r3);
  int32_t alu_out = 0;
  bool isOF = false;
  isOF = CheckOverflowForShiftLeft(r3_val, shiftBits);
  if (shiftBits < 32) {
    alu_out = r3_val << shiftBits;
  }
  set_low_register(r1, alu_out);
  SetS390ConditionCode<int32_t>(alu_out, 0);
  SetS390OverflowCode(isOF);
  return length;
}

EVALUATE(SRLK) {
  DCHECK_OPCODE(SRLK);
  // For SLLK/SRLL, the 32-bit third operand is shifted the number
  // of bits specified by the second-operand address, and the result is
  // placed at the first-operand location. Except for when the R1 and R3
  // fields designate the same register, the third operand remains
  // unchanged in general register R3.
  DECODE_RSY_A_INSTRUCTION(r1, r3, b2, d2);
  // only takes rightmost 6 bits
  uint32_t b2_val = b2 == 0 ? 0 : get_low_register<uint32_t>(b2);
  uint32_t shiftBits = (b2_val + d2) & 0x3F;
  // unsigned
  uint32_t r3_val = get_low_register<uint32_t>(r3);
  uint32_t alu_out = 0;
  if (shiftBits < 32u) {
    alu_out = r3_val >> shiftBits;
  }
  set_low_register(r1, alu_out);
  return length;
}

EVALUATE(SLLK) {
  DCHECK_OPCODE(SLLK);
  // For SLLK/SRLL, the 32-bit third operand is shifted the number
  // of bits specified by the second-operand address, and the result is
  // placed at the first-operand location. Except for when the R1 and R3
  // fields designate the same register, the third operand remains
  // unchanged in general register R3.
  DECODE_RSY_A_INSTRUCTION(r1, r3, b2, d2);
  // only takes rightmost 6 bits
  uint32_t b2_val = b2 == 0 ? 0 : get_low_register<uint32_t>(b2);
  uint32_t shiftBits = (b2_val + d2) & 0x3F;
  // unsigned
  uint32_t r3_val = get_low_register<uint32_t>(r3);
  uint32_t alu_out = 0;
  if (shiftBits < 32u) {
    alu_out = r3_val << shiftBits;
  }
  set_low_register(r1, alu_out);
  return length;
}

EVALUATE(LOCG) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(STOCG) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

#define ATOMIC_LOAD_AND_UPDATE_WORD64(op)                             \
  DECODE_RSY_A_INSTRUCTION(r1, r3, b2, d2);                           \
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);                  \
  intptr_t addr = static_cast<intptr_t>(b2_val) + d2;                 \
  int64_t r3_val = get_register(r3);                                  \
  DCHECK_EQ(addr & 0x3, 0);                                           \
  int64_t r1_val =                                                    \
      op(reinterpret_cast<int64_t*>(addr), r3_val, __ATOMIC_SEQ_CST); \
  set_register(r1, r1_val);

EVALUATE(LANG) {
  DCHECK_OPCODE(LANG);
  ATOMIC_LOAD_AND_UPDATE_WORD64(__atomic_fetch_and);
  return length;
}

EVALUATE(LAOG) {
  DCHECK_OPCODE(LAOG);
  ATOMIC_LOAD_AND_UPDATE_WORD64(__atomic_fetch_or);
  return length;
}

EVALUATE(LAXG) {
  DCHECK_OPCODE(LAXG);
  ATOMIC_LOAD_AND_UPDATE_WORD64(__atomic_fetch_xor);
  return length;
}

EVALUATE(LAAG) {
  DCHECK_OPCODE(LAAG);
  ATOMIC_LOAD_AND_UPDATE_WORD64(__atomic_fetch_add);
  return length;
}

EVALUATE(LAALG) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

#undef ATOMIC_LOAD_AND_UPDATE_WORD64

EVALUATE(LOC) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(STOC) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

#define ATOMIC_LOAD_AND_UPDATE_WORD32(op)                             \
  DECODE_RSY_A_INSTRUCTION(r1, r3, b2, d2);                           \
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);                  \
  intptr_t addr = static_cast<intptr_t>(b2_val) + d2;                 \
  int32_t r3_val = get_low_register<int32_t>(r3);                     \
  DCHECK_EQ(addr & 0x3, 0);                                           \
  int32_t r1_val =                                                    \
      op(reinterpret_cast<int32_t*>(addr), r3_val, __ATOMIC_SEQ_CST); \
  set_low_register(r1, r1_val);

EVALUATE(LAN) {
  DCHECK_OPCODE(LAN);
  ATOMIC_LOAD_AND_UPDATE_WORD32(__atomic_fetch_and);
  return length;
}

EVALUATE(LAO) {
  DCHECK_OPCODE(LAO);
  ATOMIC_LOAD_AND_UPDATE_WORD32(__atomic_fetch_or);
  return length;
}

EVALUATE(LAX) {
  DCHECK_OPCODE(LAX);
  ATOMIC_LOAD_AND_UPDATE_WORD32(__atomic_fetch_xor);
  return length;
}

EVALUATE(LAA) {
  DCHECK_OPCODE(LAA);
  ATOMIC_LOAD_AND_UPDATE_WORD32(__atomic_fetch_add);
  return length;
}

EVALUATE(LAAL) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

#undef ATOMIC_LOAD_AND_UPDATE_WORD32

EVALUATE(BRXHG) {
  DCHECK_OPCODE(BRXHG);
  DECODE_RIE_E_INSTRUCTION(r1, r3, i2);
  int64_t r1_val = (r1 == 0) ? 0 : get_register(r1);
  int64_t r3_val = (r3 == 0) ? 0 : get_register(r3);
  intptr_t branch_address = get_pc() + (2 * i2);
  r1_val += r3_val;
  int64_t compare_val = r3 % 2 == 0 ? get_register(r3 + 1) : r3_val;
  if (r1_val > compare_val) {
    set_pc(branch_address);
  }
  set_register(r1, r1_val);
  return length;
}

EVALUATE(BRXLG) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(RISBLG) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(RNSBG) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(ROSBG) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(RXSBG) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(RISBGN) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(RISBHG) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CGRJ) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CGIT) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CIT) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CLFIT) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CGIJ) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CIJ) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(ALHSIK) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(ALGHSIK) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CGRB) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CGIB) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CIB) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LDEB) {
  DCHECK_OPCODE(LDEB);
  DECODE_RXE_INSTRUCTION(r1, b2, x2, d2);
  int rb = b2;
  int rx = x2;
  int offset = d2;
  int64_t rb_val = (rb == 0) ? 0 : get_register(rb);
  int64_t rx_val = (rx == 0) ? 0 : get_register(rx);
  float fval = ReadFloat(rx_val + rb_val + offset);
  set_fpr(r1, static_cast<double>(fval));
  return length;
}

EVALUATE(LXDB) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LXEB) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(MXDB) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(KEB) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CEB) {
  DCHECK_OPCODE(CEB);

  DECODE_RXE_INSTRUCTION(r1, b2, x2, d2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  intptr_t d2_val = d2;
  float r1_val = get_fpr<float>(r1);
  float fval = ReadFloat(b2_val + x2_val + d2_val);
  SetS390ConditionCode<float>(r1_val, fval);
  return length;
}

EVALUATE(AEB) {
  DCHECK_OPCODE(AEB);
  DECODE_RXE_INSTRUCTION(r1, b2, x2, d2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  intptr_t d2_val = d2;
  float r1_val = get_fpr<float>(r1);
  float fval = ReadFloat(b2_val + x2_val + d2_val);
  r1_val += fval;
  set_fpr(r1, r1_val);
  SetS390ConditionCode<float>(r1_val, 0);
  return length;
}

EVALUATE(SEB) {
  DCHECK_OPCODE(SEB);
  DECODE_RXE_INSTRUCTION(r1, b2, x2, d2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  intptr_t d2_val = d2;
  float r1_val = get_fpr<float>(r1);
  float fval = ReadFloat(b2_val + x2_val + d2_val);
  r1_val -= fval;
  set_fpr(r1, r1_val);
  SetS390ConditionCode<float>(r1_val, 0);
  return length;
}

EVALUATE(MDEB) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(DEB) {
  DCHECK_OPCODE(DEB);
  DECODE_RXE_INSTRUCTION(r1, b2, x2, d2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  intptr_t d2_val = d2;
  float r1_val = get_fpr<float>(r1);
  float fval = ReadFloat(b2_val + x2_val + d2_val);
  r1_val /= fval;
  set_fpr(r1, r1_val);
  return length;
}

EVALUATE(MAEB) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(MSEB) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(TCEB) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(TCDB) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(TCXB) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SQEB) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SQDB) {
  DCHECK_OPCODE(SQDB);
  DECODE_RXE_INSTRUCTION(r1, b2, x2, d2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  intptr_t d2_val = d2;
  double r1_val = get_fpr<double>(r1);
  double dbl_val = ReadDouble(b2_val + x2_val + d2_val);
  r1_val = std::sqrt(dbl_val);
  set_fpr(r1, r1_val);
  return length;
}

EVALUATE(MEEB) {
  DCHECK_OPCODE(MEEB);
  DECODE_RXE_INSTRUCTION(r1, b2, x2, d2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  intptr_t d2_val = d2;
  float r1_val = get_fpr<float>(r1);
  float fval = ReadFloat(b2_val + x2_val + d2_val);
  r1_val *= fval;
  set_fpr(r1, r1_val);
  return length;
}

EVALUATE(KDB) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CDB) {
  DCHECK_OPCODE(CDB);

  DECODE_RXE_INSTRUCTION(r1, b2, x2, d2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  intptr_t d2_val = d2;
  double r1_val = get_fpr<double>(r1);
  double dbl_val = ReadDouble(b2_val + x2_val + d2_val);
  SetS390ConditionCode<double>(r1_val, dbl_val);
  return length;
}

EVALUATE(ADB) {
  DCHECK_OPCODE(ADB);

  DECODE_RXE_INSTRUCTION(r1, b2, x2, d2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  intptr_t d2_val = d2;
  double r1_val = get_fpr<double>(r1);
  double dbl_val = ReadDouble(b2_val + x2_val + d2_val);
  r1_val += dbl_val;
  set_fpr(r1, r1_val);
  SetS390ConditionCode<double>(r1_val, 0);
  return length;
}

EVALUATE(SDB) {
  DCHECK_OPCODE(SDB);
  DECODE_RXE_INSTRUCTION(r1, b2, x2, d2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  intptr_t d2_val = d2;
  double r1_val = get_fpr<double>(r1);
  double dbl_val = ReadDouble(b2_val + x2_val + d2_val);
  r1_val -= dbl_val;
  set_fpr(r1, r1_val);
  SetS390ConditionCode<double>(r1_val, 0);
  return length;
}

EVALUATE(MDB) {
  DCHECK_OPCODE(MDB);
  DECODE_RXE_INSTRUCTION(r1, b2, x2, d2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  intptr_t d2_val = d2;
  double r1_val = get_fpr<double>(r1);
  double dbl_val = ReadDouble(b2_val + x2_val + d2_val);
  r1_val *= dbl_val;
  set_fpr(r1, r1_val);
  return length;
}

EVALUATE(DDB) {
  DCHECK_OPCODE(DDB);
  DECODE_RXE_INSTRUCTION(r1, b2, x2, d2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  intptr_t d2_val = d2;
  double r1_val = get_fpr<double>(r1);
  double dbl_val = ReadDouble(b2_val + x2_val + d2_val);
  r1_val /= dbl_val;
  set_fpr(r1, r1_val);
  return length;
}

EVALUATE(MADB) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(MSDB) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SLDT) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SRDT) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SLXT) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SRXT) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(TDCET) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(TDGET) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(TDCDT) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(TDGDT) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(TDCXT) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(TDGXT) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LEY) {
  DCHECK_OPCODE(LEY);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  // Miscellaneous Loads and Stores
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  intptr_t addr = x2_val + b2_val + d2;
  float float_val = *reinterpret_cast<float*>(addr);
  set_fpr(r1, float_val);
  return length;
}

EVALUATE(LDY) {
  DCHECK_OPCODE(LDY);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  // Miscellaneous Loads and Stores
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  intptr_t addr = x2_val + b2_val + d2;
  uint64_t dbl_val = *reinterpret_cast<uint64_t*>(addr);
  set_fpr(r1, dbl_val);
  return length;
}

EVALUATE(STEY) {
  DCHECK_OPCODE(STEY);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  // Miscellaneous Loads and Stores
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  intptr_t addr = x2_val + b2_val + d2;
  int32_t frs_val = get_fpr<int32_t>(r1);
  WriteW(addr, frs_val);
  return length;
}

EVALUATE(STDY) {
  DCHECK_OPCODE(STDY);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  // Miscellaneous Loads and Stores
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  intptr_t addr = x2_val + b2_val + d2;
  int64_t frs_val = get_fpr<int64_t>(r1);
  WriteDW(addr, frs_val);
  return length;
}

EVALUATE(CZDT) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CZXT) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CDZT) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CXZT) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

#undef EVALUATE
#undef SScanF
#undef S390_SUPPORTED_VECTOR_OPCODE_LIST
#undef CheckOverflowForIntAdd
#undef CheckOverflowForIntSub
#undef CheckOverflowForUIntAdd
#undef CheckOverflowForUIntSub
#undef CheckOverflowForMul
#undef CheckOverflowForShiftRight
#undef CheckOverflowForShiftLeft
#undef DCHECK_OPCODE
#undef AS
#undef DECODE_RIL_A_INSTRUCTION
#undef DECODE_RIL_B_INSTRUCTION
#undef DECODE_RIL_C_INSTRUCTION
#undef DECODE_RXY_A_INSTRUCTION
#undef DECODE_RX_A_INSTRUCTION
#undef DECODE_RS_A_INSTRUCTION
#undef DECODE_RS_A_INSTRUCTION_NO_R3
#undef DECODE_RSI_INSTRUCTION
#undef DECODE_SI_INSTRUCTION_I_UINT8
#undef DECODE_SIL_INSTRUCTION
#undef DECODE_SIY_INSTRUCTION
#undef DECODE_RRE_INSTRUCTION
#undef DECODE_RRE_INSTRUCTION_M3
#undef DECODE_RRE_INSTRUCTION_NO_R2
#undef DECODE_RRD_INSTRUCTION
#undef DECODE_RRF_E_INSTRUCTION
#undef DECODE_RRF_A_INSTRUCTION
#undef DECODE_RRF_C_INSTRUCTION
#undef DECODE_RR_INSTRUCTION
#undef DECODE_RIE_D_INSTRUCTION
#undef DECODE_RIE_E_INSTRUCTION
#undef DECODE_RIE_F_INSTRUCTION
#undef DECODE_RSY_A_INSTRUCTION
#undef DECODE_RI_A_INSTRUCTION
#undef DECODE_RI_B_INSTRUCTION
#undef DECODE_RI_C_INSTRUCTION
#undef DECODE_RXE_INSTRUCTION
#undef DECODE_VRR_A_INSTRUCTION
#undef DECODE_VRR_B_INSTRUCTION
#undef DECODE_VRR_C_INSTRUCTION
#undef DECODE_VRR_E_INSTRUCTION
#undef DECODE_VRR_F_INSTRUCTION
#undef DECODE_VRX_INSTRUCTION
#undef DECODE_VRS_INSTRUCTION
#undef DECODE_VRI_A_INSTRUCTION
#undef DECODE_VRI_C_INSTRUCTION
#undef GET_ADDRESS
#undef VECTOR_BINARY_OP_FOR_TYPE
#undef VECTOR_BINARY_OP
#undef VECTOR_MAX_MIN_FOR_TYPE
#undef VECTOR_MAX_MIN
#undef VECTOR_COMPARE_FOR_TYPE
#undef VECTOR_COMPARE
#undef VECTOR_SHIFT_FOR_TYPE
#undef VECTOR_SHIFT
#undef VECTOR_FP_BINARY_OP
#undef VECTOR_FP_MAX_MIN_FOR_TYPE
#undef VECTOR_FP_MAX_MIN
#undef VECTOR_FP_COMPARE_FOR_TYPE
#undef VECTOR_FP_COMPARE

}  // namespace internal
}  // namespace v8

#endif  // USE_SIMULATOR
```