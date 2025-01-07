Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of the given C++ code, which is a part of a CPU simulator for the PowerPC architecture within the V8 JavaScript engine. Specifically, we need to:

* Identify the main purpose of the code.
* Determine if it's related to JavaScript execution.
* Provide examples in JavaScript if it's relevant.
* Analyze code logic and provide hypothetical inputs and outputs.
* Point out common programming errors that might relate to the simulated instructions.
* Summarize the code's functionality.

**2. Initial Analysis - Identifying Key Patterns:**

The first step is to scan the code for recurring patterns and keywords. Immediately noticeable are:

* **`case` statements within a `switch` block:** This strongly suggests the code is handling different instruction types.
* **Instruction mnemonics (like `ADDIC`, `ADDI`, `BCX`, `LWZ`, etc.):** These are typical PowerPC assembly language instructions.
* **Register manipulation (`get_register`, `set_register`, `condition_reg_`, `special_reg_xer_`, etc.):** This confirms it's simulating CPU registers.
* **Memory access (`ReadW`, `ReadDW`, `WriteW`, `WriteDW`):**  Indicates simulation of memory operations.
* **Conditional logic (if statements based on register values):**  Essential for simulating program flow.
* **Bitwise operations (>>, <<, &, |, ^):** Common in low-level CPU operations and instruction decoding/execution.

**3. High-Level Functionality Identification:**

Based on the patterns, it's clear this code simulates the execution of PowerPC instructions. The `switch` statement acts as a dispatcher, taking an instruction (presumably decoded elsewhere) and executing the corresponding simulation logic.

**4. Relationship to JavaScript:**

The code is part of V8, which is a JavaScript engine. This immediately establishes a connection. The simulator is used when V8 needs to run JavaScript code on a platform where the native architecture is *not* the host architecture. This is crucial for development, testing, and potentially for running on emulated environments.

**5. Providing JavaScript Examples:**

To illustrate the connection, we need to think about JavaScript operations that would translate to the simulated instructions. Basic arithmetic operations (`+`, `-`, comparisons `===`, `<`, `>`), bitwise operations (`&`, `|`, `^`, `>>`, `<<`), and control flow (`if`, `else`) are good candidates. The examples should be simple and directly relate to the kind of operations the simulated instructions perform.

**6. Code Logic Reasoning and Hypothetical Inputs/Outputs:**

For specific instructions, we can do a deeper dive:

* **Choose a few representative instructions:**  `ADDIC`, `CMP`, `BCX`, `LWZ` are good choices as they cover arithmetic, comparisons, branching, and memory access.
* **Trace the execution flow:**  For each instruction, follow the steps in the code:
    * What registers are read?
    * What calculations are performed?
    * What registers are written?
    * How are flags (like in the condition register) affected?
* **Invent hypothetical register values and memory contents:**  Choose values that demonstrate different execution paths (e.g., for `CMP`, values that are less than, greater than, and equal).
* **Predict the output:**  Based on the simulated logic, determine the resulting register values, memory changes, and flag settings.

**7. Identifying Common Programming Errors:**

Consider what errors a programmer might make that would trigger the behavior simulated by these instructions:

* **Integer overflow/underflow:** Instructions like `ADDIC` explicitly check for overflow, which is a common error.
* **Incorrect branching conditions:**  Simulating `BCX` helps understand how errors in branch logic can cause unexpected program flow.
* **Memory access errors:** Instructions like `LWZ` and `STW` highlight potential issues with accessing memory at invalid addresses or with incorrect data types.
* **Bitwise operation mistakes:** Instructions like `RLWIMIX` involve complex bit manipulation, where errors in the shift amounts or mask values are common.

**8. Addressing the ".tq" Question:**

The prompt asks about the `.tq` extension. Knowing that `.tq` signifies Torque code (V8's internal language), it's important to state clearly that the given code is C++ and *not* Torque.

**9. Summarizing the Functionality:**

The summary should be concise and capture the essence of the code's purpose. Focus on:

* Simulating PowerPC instructions.
* How it relates to V8 and JavaScript execution (cross-architecture support).
* The level of detail (register manipulation, memory access).

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This code just executes instructions."  **Refinement:**  It *simulates* execution, which is different from direct hardware execution.
* **Initial thought:** "The JavaScript connection isn't obvious." **Refinement:** Realize that the simulator is *part of* the JavaScript engine and used for specific scenarios. Focus on JavaScript operations that map to the simulated instructions.
* **Struggling with a complex instruction:**  Focus on the core operations of that instruction and provide a simplified example. Don't get bogged down in every single detail unless necessary for understanding.
* **Forgetting about flags:** Remember that CPU instructions often affect status flags, so pay attention to how the `condition_reg_` and `special_reg_xer_` are modified.

By following these steps, combining pattern recognition with deeper analysis of specific instructions, and keeping the overall goal in mind, we can effectively understand and explain the functionality of the given C++ code snippet.
好的，让我们来分析一下这段 `v8/src/execution/ppc/simulator-ppc.cc` 代码的功能。

**功能归纳**

这段代码是 V8 JavaScript 引擎中针对 PowerPC (PPC) 架构的**模拟器 (Simulator)** 的一部分。它的主要功能是**解释和执行 PowerPC 汇编指令**。由于真实的硬件 PPC CPU 无法直接执行 x86 或其他架构上的代码，V8 使用模拟器来在这些非 PPC 平台上运行针对 PPC 架构编译的 JavaScript 代码。

**详细功能分解**

1. **指令分发 (Instruction Dispatch):**
   - 代码使用 `switch (opcode)` 结构来根据不同的 PowerPC 指令操作码 (opcode) 分发到相应的处理代码块。
   - 每个 `case` 分支对应一个特定的 PowerPC 指令，例如 `ADDIC` (带进位的加立即数), `ADDI` (加立即数), `BCX` (条件分支) 等。

2. **寄存器模拟 (Register Simulation):**
   - 代码维护了 PPC 架构的通用寄存器 (通过 `get_register` 和 `set_register` 函数访问和修改)。
   - 它还模拟了特殊寄存器，如条件寄存器 (`condition_reg_`) 和 XER 寄存器 (`special_reg_xer_`)。

3. **算术和逻辑运算模拟:**
   - 对于算术指令 (如 `ADDIC`, `ADDI`, `SUBFCX`, `MULHWX` 等)，代码模拟了这些运算的执行过程，包括：
     - 读取操作数 (通常来自寄存器或立即数)。
     - 执行相应的算术或逻辑操作。
     - 将结果写回目标寄存器。
     - 更新状态标志 (例如，进位、溢出、零标志) 到特殊寄存器。

4. **分支指令模拟 (Branch Instruction Simulation):**
   - 对于分支指令 (如 `BCX`, `BX`, `BCLRX`, `BCCTRX`)，代码模拟了程序控制流的改变：
     - 评估分支条件 (例如，基于条件寄存器的值)。
     - 计算新的程序计数器 (PC) 值。
     - 更新 PC 寄存器，从而模拟跳转或分支。

5. **内存访问模拟 (Memory Access Simulation):**
   - 对于加载和存储指令 (如 `LWZ`, `STW`, `LBZ`, `STB`, `LFDX`, `STFDX` 等)，代码模拟了内存的读写操作：
     - 计算内存地址 (通常基于寄存器值和偏移量)。
     - 使用 `ReadW`, `ReadDW`, `WriteW`, `WriteDW` 等函数模拟从内存读取数据或将数据写入内存。

6. **条件寄存器操作模拟 (Condition Register Operation Simulation):**
   - 代码中有很多操作直接修改条件寄存器 (`condition_reg_`)，例如 `CMP`, `CMPL`, 以及带有 `. ` 后缀的指令 (如 `ADDIC.`)。它模拟了比较操作的结果如何影响条件寄存器的各个位。

7. **浮点运算模拟 (Floating-Point Operation Simulation):**
   - 代码包含了对浮点加载 (`LFSX`, `LFDX`) 和存储 (`STFSX`, `STFDX`) 指令的模拟，涉及到浮点寄存器的读写和双精度浮点数的处理。

8. **其他指令模拟:**
   - 代码还模拟了其他类型的指令，如位操作 (`RLWIMIX`, `SRWX`), 计数指令 (`POPCNTW`, `CNTLZWX`),  以及一些系统指令 (`SYNC`, `ISYNC`)。

**关于文件扩展名和 Torque**

你提到如果 `v8/src/execution/ppc/simulator-ppc.cc` 以 `.tq` 结尾，那么它将是 V8 的 Torque 源代码。这是正确的。`.tq` 文件是 V8 使用的 Torque 语言编写的，Torque 是一种用于定义 V8 内部运行时函数的领域特定语言。

**与 JavaScript 功能的关系**

`v8/src/execution/ppc/simulator-ppc.cc` 的功能与 JavaScript 的执行有直接关系。当 V8 引擎在非 PowerPC 架构上需要执行针对 PowerPC 架构编译的 JavaScript 代码时（例如，在某些嵌入式系统或交叉编译场景中），它会使用这个模拟器来逐条执行编译后的 PowerPC 机器码。

**JavaScript 示例**

以下是一些简单的 JavaScript 代码示例，以及它们在模拟器中可能涉及到的 PowerPC 指令：

```javascript
// 加法运算
let a = 10;
let b = 5;
let sum = a + b; // 可能涉及到 ADDI, ADDIC 等指令

// 条件判断
if (sum > 12) {
  console.log("Sum is greater than 12"); // 可能涉及到 CMP, BCX 等指令
}

// 访问数组元素 (内存访问)
let arr = [1, 2, 3];
let firstElement = arr[0]; // 可能涉及到 LWZ 等指令

// 位运算
let mask = 0b00001111;
let result = sum & mask; // 可能涉及到 ANDI, AND 等指令
```

当 V8 执行这些 JavaScript 代码时，如果目标架构是 PowerPC 并且运行在非 PowerPC 平台上，V8 会将这些高级操作转换为 PowerPC 机器码，并通过 `simulator-ppc.cc` 中的代码来模拟执行这些机器码。

**代码逻辑推理和假设输入/输出**

假设我们执行以下 PowerPC 指令（对应 `ADDI` 分支）：

```assembly
addi r3, r1, 10  // 将寄存器 r1 的值加上 10，结果存储到寄存器 r3
```

**假设输入:**

- 寄存器 `r1` 的值为 `5` (十进制)。

**代码执行流程 (在模拟器中):**

1. 进入 `case ADDI:` 分支。
2. `rt = instr->RTValue()` 将获取目标寄存器编号，这里是 `r3`。
3. `ra = instr->RAValue()` 将获取源寄存器编号，这里是 `r1`。
4. `im_val = SIGN_EXT_IMM16(instr->Bits(15, 0))` 将获取立即数值 `10`。
5. `ra_val = get_register(ra)` 将读取寄存器 `r1` 的值，即 `5`。
6. `alu_out = ra_val + im_val` 计算结果 `5 + 10 = 15`。
7. `set_register(rt, alu_out)` 将结果 `15` 写入寄存器 `r3`。

**输出:**

- 寄存器 `r3` 的值为 `15` (十进制)。

**用户常见的编程错误**

这段模拟器代码在某种程度上也反映了用户在编写汇编代码或底层代码时可能犯的错误：

1. **寄存器使用错误:** 错误地使用了寄存器，例如读取了未初始化的寄存器，或者将结果写入了错误的寄存器。
2. **立即数范围错误:**  某些指令的立即数有范围限制，超出范围可能导致不可预测的结果。
3. **内存访问错误:**
   - 访问了无效的内存地址（例如，空指针解引用）。
   - 读写了错误大小的数据（例如，尝试将一个字节写入到需要字的内存位置）。
   - 没有正确对齐内存访问。
4. **分支条件错误:** 在编写条件分支时，逻辑判断错误可能导致程序执行流程出错。
5. **算术溢出/下溢:**  没有正确处理算术运算可能导致的溢出或下溢情况。例如，`ADDIC` 指令会设置进位标志，如果程序员没有检查这个标志，可能会导致逻辑错误。

**代码示例 (可能导致错误的 JavaScript，对应模拟器中的指令):**

```javascript
// 潜在的溢出 (对应 ADDIC 等)
let maxInt = 2147483647;
let overflow = maxInt + 1; // 在某些上下文中可能导致溢出，模拟器会反映状态

// 错误的内存访问 (对应 LWZ, STW 等)
// 在 JavaScript 中不容易直接触发这种底层错误，但在编译后的代码中可能出现
// 例如，如果底层实现错误地计算了内存地址

// 分支条件错误 (对应 CMP, BCX 等)
let x = 5;
if (x < 0) { // 假设本意是 x > 0
  console.log("x is negative");
}
```

**归纳一下它的功能 (第 3 部分)**

这段代码是 `v8/src/execution/ppc/simulator-ppc.cc` 的一部分，负责模拟 PowerPC 架构中**算术运算、逻辑运算、分支控制和基本的内存访问指令**的执行。它是整个 PowerPC 模拟器的核心组成部分，通过解释和执行这些指令，使得 V8 能够在非 PowerPC 平台上运行为 PowerPC 架构编译的 JavaScript 代码。这一部分主要关注各种不同的指令 `case` 分支的实现细节。

Prompt: 
```
这是目录为v8/src/execution/ppc/simulator-ppc.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/ppc/simulator-ppc.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共6部分，请归纳一下它的功能

"""
t_register(ra);
        if (ra_val < im_val) {
          bf |= 0x80000000;
        }
        if (ra_val > im_val) {
          bf |= 0x40000000;
        }
        if (ra_val == im_val) {
          bf |= 0x20000000;
        }
      }
      uint32_t condition_mask = 0xF0000000U >> (cr * 4);
      uint32_t condition = bf >> (cr * 4);
      condition_reg_ = (condition_reg_ & ~condition_mask) | condition;
      break;
    }
    case ADDIC: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      uintptr_t ra_val = get_register(ra);
      uintptr_t im_val = SIGN_EXT_IMM16(instr->Bits(15, 0));
      uintptr_t alu_out = ra_val + im_val;
      // Check overflow
      if (~ra_val < im_val) {
        special_reg_xer_ = (special_reg_xer_ & ~0xF0000000) | 0x20000000;
      } else {
        special_reg_xer_ &= ~0xF0000000;
      }
      set_register(rt, alu_out);
      break;
    }
    case ADDI: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int32_t im_val = SIGN_EXT_IMM16(instr->Bits(15, 0));
      intptr_t alu_out;
      if (ra == 0) {
        alu_out = im_val;
      } else {
        intptr_t ra_val = get_register(ra);
        alu_out = ra_val + im_val;
      }
      set_register(rt, alu_out);
      // todo - handle RC bit
      break;
    }
    case ADDIS: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int32_t im_val = (instr->Bits(15, 0) << 16);
      intptr_t alu_out;
      if (ra == 0) {  // treat r0 as zero
        alu_out = im_val;
      } else {
        intptr_t ra_val = get_register(ra);
        alu_out = ra_val + im_val;
      }
      set_register(rt, alu_out);
      break;
    }
    case BCX: {
      ExecuteBranchConditional(instr, BC_OFFSET);
      break;
    }
    case BX: {
      int offset = (instr->Bits(25, 2) << 8) >> 6;
      if (instr->Bit(0) == 1) {  // LK flag set
        special_reg_lr_ = get_pc() + 4;
      }
      set_pc(get_pc() + offset);
      // todo - AA flag
      break;
    }
    case MCRF:
      UNIMPLEMENTED();  // Not used by V8.
    case BCLRX:
      ExecuteBranchConditional(instr, BC_LINK_REG);
      break;
    case BCCTRX:
      ExecuteBranchConditional(instr, BC_CTR_REG);
      break;
    case CRNOR:
    case RFI:
    case CRANDC:
      UNIMPLEMENTED();
    case ISYNC: {
      // todo - simulate isync
      break;
    }
    case CRXOR: {
      int bt = instr->Bits(25, 21);
      int ba = instr->Bits(20, 16);
      int bb = instr->Bits(15, 11);
      int ba_val = ((0x80000000 >> ba) & condition_reg_) == 0 ? 0 : 1;
      int bb_val = ((0x80000000 >> bb) & condition_reg_) == 0 ? 0 : 1;
      int bt_val = ba_val ^ bb_val;
      bt_val = bt_val << (31 - bt);  // shift bit to correct destination
      condition_reg_ &= ~(0x80000000 >> bt);
      condition_reg_ |= bt_val;
      break;
    }
    case CREQV: {
      int bt = instr->Bits(25, 21);
      int ba = instr->Bits(20, 16);
      int bb = instr->Bits(15, 11);
      int ba_val = ((0x80000000 >> ba) & condition_reg_) == 0 ? 0 : 1;
      int bb_val = ((0x80000000 >> bb) & condition_reg_) == 0 ? 0 : 1;
      int bt_val = 1 - (ba_val ^ bb_val);
      bt_val = bt_val << (31 - bt);  // shift bit to correct destination
      condition_reg_ &= ~(0x80000000 >> bt);
      condition_reg_ |= bt_val;
      break;
    }
    case CRNAND:
    case CRAND:
    case CRORC:
    case CROR: {
      UNIMPLEMENTED();  // Not used by V8.
    }
    case RLWIMIX: {
      int ra = instr->RAValue();
      int rs = instr->RSValue();
      uint32_t rs_val = get_register(rs);
      int32_t ra_val = get_register(ra);
      int sh = instr->Bits(15, 11);
      int mb = instr->Bits(10, 6);
      int me = instr->Bits(5, 1);
      uint32_t result = base::bits::RotateLeft32(rs_val, sh);
      int mask = 0;
      if (mb < me + 1) {
        int bit = 0x80000000 >> mb;
        for (; mb <= me; mb++) {
          mask |= bit;
          bit >>= 1;
        }
      } else if (mb == me + 1) {
        mask = 0xFFFFFFFF;
      } else {                             // mb > me+1
        int bit = 0x80000000 >> (me + 1);  // needs to be tested
        mask = 0xFFFFFFFF;
        for (; me < mb; me++) {
          mask ^= bit;
          bit >>= 1;
        }
      }
      result &= mask;
      ra_val &= ~mask;
      result |= ra_val;
      set_register(ra, result);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(result);
      }
      break;
    }
    case RLWINMX:
    case RLWNMX: {
      int ra = instr->RAValue();
      int rs = instr->RSValue();
      uint32_t rs_val = get_register(rs);
      int sh = 0;
      if (opcode == RLWINMX) {
        sh = instr->Bits(15, 11);
      } else {
        int rb = instr->RBValue();
        uint32_t rb_val = get_register(rb);
        sh = (rb_val & 0x1F);
      }
      int mb = instr->Bits(10, 6);
      int me = instr->Bits(5, 1);
      uint32_t result = base::bits::RotateLeft32(rs_val, sh);
      int mask = 0;
      if (mb < me + 1) {
        int bit = 0x80000000 >> mb;
        for (; mb <= me; mb++) {
          mask |= bit;
          bit >>= 1;
        }
      } else if (mb == me + 1) {
        mask = 0xFFFFFFFF;
      } else {                             // mb > me+1
        int bit = 0x80000000 >> (me + 1);  // needs to be tested
        mask = 0xFFFFFFFF;
        for (; me < mb; me++) {
          mask ^= bit;
          bit >>= 1;
        }
      }
      result &= mask;
      set_register(ra, result);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(result);
      }
      break;
    }
    case ORI: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      intptr_t rs_val = get_register(rs);
      uint32_t im_val = instr->Bits(15, 0);
      intptr_t alu_out = rs_val | im_val;
      set_register(ra, alu_out);
      break;
    }
    case ORIS: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      intptr_t rs_val = get_register(rs);
      uint32_t im_val = instr->Bits(15, 0);
      intptr_t alu_out = rs_val | (im_val << 16);
      set_register(ra, alu_out);
      break;
    }
    case XORI: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      intptr_t rs_val = get_register(rs);
      uint32_t im_val = instr->Bits(15, 0);
      intptr_t alu_out = rs_val ^ im_val;
      set_register(ra, alu_out);
      // todo - set condition based SO bit
      break;
    }
    case XORIS: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      intptr_t rs_val = get_register(rs);
      uint32_t im_val = instr->Bits(15, 0);
      intptr_t alu_out = rs_val ^ (im_val << 16);
      set_register(ra, alu_out);
      break;
    }
    case ANDIx: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      intptr_t rs_val = get_register(rs);
      uint32_t im_val = instr->Bits(15, 0);
      intptr_t alu_out = rs_val & im_val;
      set_register(ra, alu_out);
      SetCR0(alu_out);
      break;
    }
    case ANDISx: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      intptr_t rs_val = get_register(rs);
      uint32_t im_val = instr->Bits(15, 0);
      intptr_t alu_out = rs_val & (im_val << 16);
      set_register(ra, alu_out);
      SetCR0(alu_out);
      break;
    }
    case SRWX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      uint32_t rs_val = get_register(rs);
      uintptr_t rb_val = get_register(rb) & 0x3F;
      intptr_t result = (rb_val > 31) ? 0 : rs_val >> rb_val;
      set_register(ra, result);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(result);
      }
      break;
    }
    case SRDX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      uintptr_t rs_val = get_register(rs);
      uintptr_t rb_val = get_register(rb) & 0x7F;
      intptr_t result = (rb_val > 63) ? 0 : rs_val >> rb_val;
      set_register(ra, result);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(result);
      }
      break;
    }
    case MODUW: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      uint32_t ra_val = get_register(ra);
      uint32_t rb_val = get_register(rb);
      uint32_t alu_out = (rb_val == 0) ? -1 : ra_val % rb_val;
      set_register(rt, alu_out);
      break;
    }
    case MODUD: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      uint64_t ra_val = get_register(ra);
      uint64_t rb_val = get_register(rb);
      uint64_t alu_out = (rb_val == 0) ? -1 : ra_val % rb_val;
      set_register(rt, alu_out);
      break;
    }
    case MODSW: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      int32_t ra_val = get_register(ra);
      int32_t rb_val = get_register(rb);
      bool overflow = (ra_val == kMinInt && rb_val == -1);
      // result is undefined if divisor is zero or if operation
      // is 0x80000000 / -1.
      int32_t alu_out = (rb_val == 0 || overflow) ? -1 : ra_val % rb_val;
      set_register(rt, alu_out);
      break;
    }
    case MODSD: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      int64_t ra_val = get_register(ra);
      int64_t rb_val = get_register(rb);
      int64_t one = 1;  // work-around gcc
      int64_t kMinLongLong = (one << 63);
      // result is undefined if divisor is zero or if operation
      // is 0x80000000_00000000 / -1.
      int64_t alu_out =
          (rb_val == 0 || (ra_val == kMinLongLong && rb_val == -1))
              ? -1
              : ra_val % rb_val;
      set_register(rt, alu_out);
      break;
    }
    case SRAW: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      int32_t rs_val = get_register(rs);
      intptr_t rb_val = get_register(rb) & 0x3F;
      intptr_t result = (rb_val > 31) ? rs_val >> 31 : rs_val >> rb_val;
      set_register(ra, result);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(result);
      }
      break;
    }
    case SRAD: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t rs_val = get_register(rs);
      intptr_t rb_val = get_register(rb) & 0x7F;
      intptr_t result = (rb_val > 63) ? rs_val >> 63 : rs_val >> rb_val;
      set_register(ra, result);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(result);
      }
      break;
    }
    case SRAWIX: {
      int ra = instr->RAValue();
      int rs = instr->RSValue();
      int sh = instr->Bits(15, 11);
      int32_t rs_val = get_register(rs);
      intptr_t result = rs_val >> sh;
      set_register(ra, result);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(result);
      }
      break;
    }
    case EXTSW: {
      const int shift = kBitsPerSystemPointer - 32;
      int ra = instr->RAValue();
      int rs = instr->RSValue();
      intptr_t rs_val = get_register(rs);
      intptr_t ra_val = (rs_val << shift) >> shift;
      set_register(ra, ra_val);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(ra_val);
      }
      break;
    }
    case EXTSH: {
      const int shift = kBitsPerSystemPointer - 16;
      int ra = instr->RAValue();
      int rs = instr->RSValue();
      intptr_t rs_val = get_register(rs);
      intptr_t ra_val = (rs_val << shift) >> shift;
      set_register(ra, ra_val);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(ra_val);
      }
      break;
    }
    case EXTSB: {
      const int shift = kBitsPerSystemPointer - 8;
      int ra = instr->RAValue();
      int rs = instr->RSValue();
      intptr_t rs_val = get_register(rs);
      intptr_t ra_val = (rs_val << shift) >> shift;
      set_register(ra, ra_val);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(ra_val);
      }
      break;
    }
    case LFSUX:
    case LFSX: {
      int frt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      intptr_t rb_val = get_register(rb);
      int32_t val = ReadW(ra_val + rb_val);
      float* fptr = reinterpret_cast<float*>(&val);
#if V8_HOST_ARCH_IA32 || V8_HOST_ARCH_X64
      // Conversion using double changes sNan to qNan on ia32/x64
      if ((val & 0x7F800000) == 0x7F800000) {
        int64_t dval = static_cast<int64_t>(val);
        dval = ((dval & 0xC0000000) << 32) | ((dval & 0x40000000) << 31) |
               ((dval & 0x40000000) << 30) | ((dval & 0x7FFFFFFF) << 29) | 0x0;
        set_d_register(frt, dval);
      } else {
        set_d_register_from_double(frt, static_cast<double>(*fptr));
      }
#else
      set_d_register_from_double(frt, static_cast<double>(*fptr));
#endif
      if (opcode == LFSUX) {
        DCHECK_NE(ra, 0);
        set_register(ra, ra_val + rb_val);
      }
      break;
    }
    case LFDUX:
    case LFDX: {
      int frt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      intptr_t rb_val = get_register(rb);
      int64_t dptr = ReadDW(ra_val + rb_val);
      set_d_register(frt, dptr);
      if (opcode == LFDUX) {
        DCHECK_NE(ra, 0);
        set_register(ra, ra_val + rb_val);
      }
      break;
    }
    case STFSUX:
      [[fallthrough]];
    case STFSX: {
      int frs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      intptr_t rb_val = get_register(rb);
      float frs_val = static_cast<float>(get_double_from_d_register(frs));
      int32_t* p = reinterpret_cast<int32_t*>(&frs_val);
#if V8_HOST_ARCH_IA32 || V8_HOST_ARCH_X64
      // Conversion using double changes sNan to qNan on ia32/x64
      int32_t sval = 0;
      int64_t dval = get_d_register(frs);
      if ((dval & 0x7FF0000000000000) == 0x7FF0000000000000) {
        sval = ((dval & 0xC000000000000000) >> 32) |
               ((dval & 0x07FFFFFFE0000000) >> 29);
        p = &sval;
      } else {
        p = reinterpret_cast<int32_t*>(&frs_val);
      }
#else
      p = reinterpret_cast<int32_t*>(&frs_val);
#endif
      WriteW(ra_val + rb_val, *p);
      if (opcode == STFSUX) {
        DCHECK_NE(ra, 0);
        set_register(ra, ra_val + rb_val);
      }
      break;
    }
    case STFDUX:
      [[fallthrough]];
    case STFDX: {
      int frs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      intptr_t rb_val = get_register(rb);
      int64_t frs_val = get_d_register(frs);
      WriteDW(ra_val + rb_val, frs_val);
      if (opcode == STFDUX) {
        DCHECK_NE(ra, 0);
        set_register(ra, ra_val + rb_val);
      }
      break;
    }
    case POPCNTW: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      uintptr_t rs_val = get_register(rs);
      uintptr_t count = 0;
      int n = 0;
      uintptr_t bit = 0x80000000;
      for (; n < 32; n++) {
        if (bit & rs_val) count++;
        bit >>= 1;
      }
      set_register(ra, count);
      break;
    }
    case POPCNTD: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      uintptr_t rs_val = get_register(rs);
      uintptr_t count = 0;
      int n = 0;
      uintptr_t bit = 0x8000000000000000UL;
      for (; n < 64; n++) {
        if (bit & rs_val) count++;
        bit >>= 1;
      }
      set_register(ra, count);
      break;
    }
    case SYNC: {
      // todo - simulate sync
      __sync_synchronize();
      break;
    }
    case ICBI: {
      // todo - simulate icbi
      break;
    }

    case LWZU:
    case LWZ: {
      int ra = instr->RAValue();
      int rt = instr->RTValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      int offset = SIGN_EXT_IMM16(instr->Bits(15, 0));
      set_register(rt, ReadWU(ra_val + offset));
      if (opcode == LWZU) {
        DCHECK_NE(ra, 0);
        set_register(ra, ra_val + offset);
      }
      break;
    }

    case LBZU:
    case LBZ: {
      int ra = instr->RAValue();
      int rt = instr->RTValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      int offset = SIGN_EXT_IMM16(instr->Bits(15, 0));
      set_register(rt, ReadB(ra_val + offset) & 0xFF);
      if (opcode == LBZU) {
        DCHECK_NE(ra, 0);
        set_register(ra, ra_val + offset);
      }
      break;
    }

    case STWU:
    case STW: {
      int ra = instr->RAValue();
      int rs = instr->RSValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      int32_t rs_val = get_register(rs);
      int offset = SIGN_EXT_IMM16(instr->Bits(15, 0));
      WriteW(ra_val + offset, rs_val);
      if (opcode == STWU) {
        DCHECK_NE(ra, 0);
        set_register(ra, ra_val + offset);
      }
      break;
    }
    case SRADIX: {
      int ra = instr->RAValue();
      int rs = instr->RSValue();
      int sh = (instr->Bits(15, 11) | (instr->Bit(1) << 5));
      intptr_t rs_val = get_register(rs);
      intptr_t result = rs_val >> sh;
      set_register(ra, result);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(result);
      }
      break;
    }
    case STBCX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      int8_t rs_val = get_register(rs);
      intptr_t rb_val = get_register(rb);
      SetCR0(WriteExB(ra_val + rb_val, rs_val));
      break;
    }
    case STHCX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      int16_t rs_val = get_register(rs);
      intptr_t rb_val = get_register(rb);
      SetCR0(WriteExH(ra_val + rb_val, rs_val));
      break;
    }
    case STWCX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      int32_t rs_val = get_register(rs);
      intptr_t rb_val = get_register(rb);
      SetCR0(WriteExW(ra_val + rb_val, rs_val));
      break;
    }
    case STDCX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t ra_val = ra == 0 ? 0 : get_register(ra);
      int64_t rs_val = get_register(rs);
      intptr_t rb_val = get_register(rb);
      SetCR0(WriteExDW(ra_val + rb_val, rs_val));
      break;
    }
    case TW: {
      // used for call redirection in simulation mode
      SoftwareInterrupt(instr);
      break;
    }
    case CMP: {
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      int cr = instr->Bits(25, 23);
      uint32_t bf = 0;
      int L = instr->Bit(21);
      if (L) {
        intptr_t ra_val = get_register(ra);
        intptr_t rb_val = get_register(rb);
        if (ra_val < rb_val) {
          bf |= 0x80000000;
        }
        if (ra_val > rb_val) {
          bf |= 0x40000000;
        }
        if (ra_val == rb_val) {
          bf |= 0x20000000;
        }
      } else {
        int32_t ra_val = get_register(ra);
        int32_t rb_val = get_register(rb);
        if (ra_val < rb_val) {
          bf |= 0x80000000;
        }
        if (ra_val > rb_val) {
          bf |= 0x40000000;
        }
        if (ra_val == rb_val) {
          bf |= 0x20000000;
        }
      }
      uint32_t condition_mask = 0xF0000000U >> (cr * 4);
      uint32_t condition = bf >> (cr * 4);
      condition_reg_ = (condition_reg_ & ~condition_mask) | condition;
      break;
    }
    case SUBFCX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      // int oe = instr->Bit(10);
      uintptr_t ra_val = get_register(ra);
      uintptr_t rb_val = get_register(rb);
      uintptr_t alu_out = ~ra_val + rb_val + 1;
      // Set carry
      if (ra_val <= rb_val) {
        special_reg_xer_ = (special_reg_xer_ & ~0xF0000000) | 0x20000000;
      } else {
        special_reg_xer_ &= ~0xF0000000;
      }
      set_register(rt, alu_out);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(alu_out);
      }
      // todo - handle OE bit
      break;
    }
    case SUBFEX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      // int oe = instr->Bit(10);
      uintptr_t ra_val = get_register(ra);
      uintptr_t rb_val = get_register(rb);
      uintptr_t alu_out = ~ra_val + rb_val;
      if (special_reg_xer_ & 0x20000000) {
        alu_out += 1;
      }
      set_register(rt, alu_out);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(static_cast<intptr_t>(alu_out));
      }
      // todo - handle OE bit
      break;
    }
    case ADDCX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      // int oe = instr->Bit(10);
      uintptr_t ra_val = get_register(ra);
      uintptr_t rb_val = get_register(rb);
      uintptr_t alu_out = ra_val + rb_val;
      // Set carry
      if (~ra_val < rb_val) {
        special_reg_xer_ = (special_reg_xer_ & ~0xF0000000) | 0x20000000;
      } else {
        special_reg_xer_ &= ~0xF0000000;
      }
      set_register(rt, alu_out);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(static_cast<intptr_t>(alu_out));
      }
      // todo - handle OE bit
      break;
    }
    case ADDEX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      // int oe = instr->Bit(10);
      uintptr_t ra_val = get_register(ra);
      uintptr_t rb_val = get_register(rb);
      uintptr_t alu_out = ra_val + rb_val;
      if (special_reg_xer_ & 0x20000000) {
        alu_out += 1;
      }
      set_register(rt, alu_out);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(static_cast<intptr_t>(alu_out));
      }
      // todo - handle OE bit
      break;
    }
    case MULHWX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      int32_t ra_val = (get_register(ra) & 0xFFFFFFFF);
      int32_t rb_val = (get_register(rb) & 0xFFFFFFFF);
      int64_t alu_out = (int64_t)ra_val * (int64_t)rb_val;
      // High 32 bits of the result is undefined,
      // Which is simulated here by adding random bits.
      alu_out = (alu_out >> 32) | 0x421000000000000;
      set_register(rt, alu_out);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(static_cast<intptr_t>(alu_out));
      }
      break;
    }
    case MULHWUX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      uint32_t ra_val = (get_register(ra) & 0xFFFFFFFF);
      uint32_t rb_val = (get_register(rb) & 0xFFFFFFFF);
      uint64_t alu_out = (uint64_t)ra_val * (uint64_t)rb_val;
      // High 32 bits of the result is undefined,
      // Which is simulated here by adding random bits.
      alu_out = (alu_out >> 32) | 0x421000000000000;
      set_register(rt, alu_out);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(static_cast<intptr_t>(alu_out));
      }
      break;
    }
    case MULHD: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      int64_t ra_val = get_register(ra);
      int64_t rb_val = get_register(rb);
      int64_t alu_out = base::bits::SignedMulHigh64(ra_val, rb_val);
      set_register(rt, alu_out);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(static_cast<intptr_t>(alu_out));
      }
      break;
    }
    case MULHDU: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      uint64_t ra_val = get_register(ra);
      uint64_t rb_val = get_register(rb);
      uint64_t alu_out = base::bits::UnsignedMulHigh64(ra_val, rb_val);
      set_register(rt, alu_out);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(static_cast<intptr_t>(alu_out));
      }
      break;
    }
    case NEGX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      intptr_t ra_val = get_register(ra);
      intptr_t alu_out = 1 + ~ra_val;
      intptr_t one = 1;  // work-around gcc
      intptr_t kOverflowVal = (one << 63);
      set_register(rt, alu_out);
      if (instr->Bit(10)) {  // OE bit set
        if (ra_val == kOverflowVal) {
          special_reg_xer_ |= 0xC0000000;  // set SO,OV
        } else {
          special_reg_xer_ &= ~0x40000000;  // clear OV
        }
      }
      if (instr->Bit(0)) {  // RC bit set
        bool setSO = (special_reg_xer_ & 0x80000000);
        SetCR0(alu_out, setSO);
      }
      break;
    }
    case SLWX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      uint32_t rs_val = get_register(rs);
      uintptr_t rb_val = get_register(rb) & 0x3F;
      uint32_t result = (rb_val > 31) ? 0 : rs_val << rb_val;
      set_register(ra, result);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(result);
      }
      break;
    }
    case SLDX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      uintptr_t rs_val = get_register(rs);
      uintptr_t rb_val = get_register(rb) & 0x7F;
      uintptr_t result = (rb_val > 63) ? 0 : rs_val << rb_val;
      set_register(ra, result);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(result);
      }
      break;
    }
    case MFVSRD: {
      int frt = instr->RTValue();
      int ra = instr->RAValue();
      int64_t frt_val;
      if (!instr->Bit(0)) {
        // if double reg (TX=0).
        frt_val = get_d_register(frt);
      } else {
        // if simd reg (TX=1).
        DCHECK_EQ(instr->Bit(0), 1);
        frt_val = get_simd_register_by_lane<int64_t>(frt, 0);
      }
      set_register(ra, frt_val);
      break;
    }
    case MFVSRWZ: {
      DCHECK(!instr->Bit(0));
      int frt = instr->RTValue();
      int ra = instr->RAValue();
      int64_t frt_val = get_d_register(frt);
      set_register(ra, static_cast<uint32_t>(frt_val));
      break;
    }
    case MTVSRD: {
      int frt = instr->RTValue();
      int ra = instr->RAValue();
      int64_t ra_val = get_register(ra);
      if (!instr->Bit(0)) {
        // if double reg (TX=0).
        set_d_register(frt, ra_val);
      } else {
        // if simd reg (TX=1).
        DCHECK_EQ(instr->Bit(0), 1);
        set_simd_register_by_lane<int64_t>(frt, 0,
                                           static_cast<int64_t>(ra_val));
        // Low 64 bits of the result is undefined,
        // Which is simulated here by adding random bits.
        set_simd_register_by_lane<int64_t>(
            frt, 1, static_cast<int64_t>(0x123456789ABCD));
      }
      break;
    }
    case MTVSRDD: {
      int xt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      set_simd_register_by_lane<int64_t>(
          xt, 0, static_cast<int64_t>(get_register(ra)));
      set_simd_register_by_lane<int64_t>(
          xt, 1, static_cast<int64_t>(get_register(rb)));
      break;
    }
    case MTVSRWA: {
      DCHECK(!instr->Bit(0));
      int frt = instr->RTValue();
      int ra = instr->RAValue();
      int64_t ra_val = static_cast<int32_t>(get_register(ra));
      set_d_register(frt, ra_val);
      break;
    }
    case MTVSRWZ: {
      DCHECK(!instr->Bit(0));
      int frt = instr->RTValue();
      int ra = instr->RAValue();
      uint64_t ra_val = static_cast<uint32_t>(get_register(ra));
      set_d_register(frt, ra_val);
      break;
    }
    case CNTLZWX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      uintptr_t rs_val = get_register(rs);
      uintptr_t count = 0;
      int n = 0;
      uintptr_t bit = 0x80000000;
      for (; n < 32; n++) {
        if (bit & rs_val) break;
        count++;
        bit >>= 1;
      }
      set_register(ra, count);
      if (instr->Bit(0)) {  // RC Bit set
        int bf = 0;
        if (count > 0) {
          bf |= 0x40000000;
        }
        if (count == 0) {
          bf |= 0x20000000;
        }
        condition_reg_ = (condition_reg_ & ~0xF0000000) | bf;
      }
      break;
    }
    case CNTLZDX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      uintptr_t rs_val = get_register(rs);
      uintptr_t count = 0;
      int n = 0;
      uintptr_t bit = 0x8000000000000000UL;
      for (; n < 64; n++) {
        if (bit & rs_val) break;
        count++;
        bit >>= 1;
      }
      set_register(ra, count);
      if (instr->Bit(0)) {  // RC Bit set
        int bf = 0;
        if (count > 0) {
          bf |= 0x40000000;
        }
        if (count == 0) {
          bf |= 0x20000000;
        }
        condition_reg_ = (condition_reg_ & ~0xF0000000) | bf;
      }
      break;
    }
    case CNTTZWX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      uint32_t rs_val = static_cast<uint32_t>(get_register(rs));
      uintptr_t count = rs_val == 0 ? 32 : __builtin_ctz(rs_val);
      set_register(ra, count);
      if (instr->Bit(0)) {  // RC Bit set
        int bf = 0;
        if (count > 0) {
          bf |= 0x40000000;
        }
        if (count == 0) {
          bf |= 0x20000000;
        }
        condition_reg_ = (condition_reg_ & ~0xF0000000) | bf;
      }
      break;
    }
    case CNTTZDX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      uint64_t rs_val = get_register(rs);
      uintptr_t count = rs_val == 0 ? 64 : __builtin_ctzl(rs_val);
      set_register(ra, count);
      if (instr->Bit(0)) {  // RC Bit set
        int bf = 0;
        if (count > 0) {
          bf |= 0x40000000;
        }
        if (count == 0) {
          bf |= 0x20000000;
        }
        condition_reg_ = (condition_reg_ & ~0xF0000000) | bf;
      }
      break;
    }
    case ANDX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t rs_val = get_register(rs);
      intptr_t rb_val = get_register(rb);
      intptr_t alu_out = rs_val & rb_val;
      set_register(ra, alu_out);
      if (instr->Bit(0)) {  // RC Bit set
        SetCR0(alu_out);
      }
      break;
    }
    case ANDCX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t rs_val = get_register(rs);
      intptr_t rb_val = get_register(rb);
      intptr_t alu_out = rs_val & ~rb_val;
      set_register(ra, alu_out);
      if (instr->Bit(0)) {  // RC Bit set
        SetCR0(alu_out);
      }
      break;
    }
    case CMPL: {
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      int cr = instr->Bits(25, 23);
      uint32_t bf = 0;
      int L = instr->Bit(21);
      if (L) {
        uintptr_t ra_val = get_register(ra);
        uintptr_t rb_val = get_register(rb);
        if (ra_val < rb_val) {
          bf |= 0x80000000;
        }
        if (ra_val > rb_val) {
          bf |= 0x40000000;
        }
        if (ra_val == rb_val) {
          bf |= 0x20000000;
        }
      } else {
        uint32_t ra_val = get_register(ra);
        uint32_t rb_val = get_register(rb);
        if (ra_val < rb_val) {
          bf |= 0x80000000;
        }
        if (ra_val > rb_val) {
          bf |= 0x40000000;
        }
        if (ra_val == rb_val) {
          bf |= 0x20000000;
        }
      }
      uint32_t condition_mask = 0xF0000000U >> (cr * 4);
      uint32_t condition = bf >> (cr * 4);
      condition_reg_ = (condition_reg_ & ~condition_mask) | condition;
      break;
    }
    case SUBFX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      // int oe = instr->Bit(10);
      intptr_t ra_val = get_register(ra);
      intptr_t rb_val = get_register(rb);
      intptr_t alu_out = rb_val - ra_val;
      // todo - figure out underflow
      set_register(rt, alu_out);
      if (instr->Bit(0)) {  // RC Bit set
        SetCR0(alu_out);
      }
      // todo - handle OE bit
      break;
    }
    case ADDZEX: {
      int rt = instr->RTValue();
      int ra = instr->RAValue();
      intptr_t ra_val = get_register(ra);
      if (special_reg_xer_ & 0x20000000) {
        ra_val += 1;
      }
      set_register(rt, ra_val);
      if (instr->Bit(0)) {  // RC bit set
        SetCR0(ra_val);
      }
      // todo - handle OE bit
      break;
    }
    case NORX: {
      int rs = instr->RSValue();
      int ra = instr->RAValue();
      int rb = instr->RBValue();
      intptr_t rs_val = get_register(rs);
      intptr_t rb_val = get_register(rb);
      intptr_t alu_out = ~(rs_val | rb_val);
      set_register(ra, alu_out
"""


```