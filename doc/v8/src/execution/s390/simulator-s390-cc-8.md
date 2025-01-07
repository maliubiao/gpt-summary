Response:
The user wants a summary of the functionality of the provided C++ code snippet. This code appears to be part of a simulator for the s390 architecture within the V8 JavaScript engine.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Functionality:** The code uses macros like `EVALUATE`, `DCHECK_OPCODE`, `DECODE_RRF_A_INSTRUCTION`, etc. These suggest that the code is simulating individual s390 instructions. Each `EVALUATE` block likely corresponds to a specific s390 opcode.

2. **Analyze Instruction Types:** The `DECODE_*_INSTRUCTION` macros indicate different instruction formats (RRF_A, RRF_C, RXY_A, RSY_A, SIL). This is important for understanding how operands are fetched and used.

3. **Focus on the Actions Within Each `EVALUATE` Block:**  The core of each block involves:
    * Decoding the instruction to get operands (registers, immediate values, memory addresses).
    * Reading register values using `get_register` or `get_low_register`.
    * Performing operations (arithmetic, bitwise, memory access, shifts).
    * Writing results back to registers using `set_register` or `set_low_register`.
    * Setting condition codes and overflow flags.
    * Returning the instruction length.

4. **Categorize Instructions:** Observe patterns in the operations. Group instructions based on their function:
    * **Arithmetic:** Addition (AGRK, ARK, AG, AY, AHY), Subtraction (SGRK, SRK, SG, SY, SHY), Multiplication (MSG, MSGF, MSY, MSC, MFY, ML), Division (DSG, DSGF, DLG, DL).
    * **Bitwise:** AND (NRK, NY, NG), OR (ORK, OY, OG), XOR (XRK, XY, XG).
    * **Load/Store:** Loading from memory into registers (LTG, LT, LGH, LLGF, LB, LGB, LHY, LLGH, LLH, LMG), storing from registers to memory (STRV, STRVG, STRVH, STHY, STCY, MVGHI, MVHI).
    * **Comparison:** Comparing values and setting condition codes (CG, CLG, CY).
    * **Shift:** Logical and Arithmetic shifts (SRAG, SLAG, SRLG, SLLG).
    * **Address Calculation:** Calculating memory addresses (LAY).
    * **Other:**  Byte reversal (LRVG, LRV, LRVH), conditional moves (LOCR), unimplemented instructions.

5. **Address the Specific Questions:**

    * **Functionality:** List the identified categories and specific operations.
    * **Torque:** Explain that `.tq` signifies Torque and that this file is C++, so it's not Torque.
    * **JavaScript Relationship:**  Explain the role of the simulator in executing JavaScript and provide a simple example where these low-level operations would be involved (addition).
    * **Code Logic Reasoning:** Choose a simple arithmetic instruction (e.g., `AGRK`) and provide example input register values and the expected output and condition codes.
    * **Common Programming Errors:** Explain how integer overflow can occur in these operations and provide a JavaScript example that would lead to such an overflow.

6. **Summarize Overall Functionality:**  Reiterate that this code simulates the s390 architecture to enable V8 to run on that platform.

7. **Consider the "Part 9 of 10" aspect:** Acknowledge this and state that this part focuses on a specific subset of instructions, likely arithmetic, logical, load/store operations.

8. **Refine and Organize:**  Structure the answer logically with clear headings and explanations. Use precise terminology. Ensure the examples are relevant and easy to understand. Double-check for consistency and accuracy.
这是目录为 `v8/src/execution/s390/simulator-s390.cc` 的一个 V8 源代码片段，它是一个 **C++** 文件，用于实现 **s390 架构的指令模拟器**。

以下是它的功能列表：

1. **指令模拟执行:**  该文件中的代码定义了许多 `EVALUATE` 宏，每个宏对应一个特定的 s390 指令（例如 `SGRK`, `ALGRK`, `LTG`, `AG`, `SG` 等）。这些宏内部包含了模拟该指令在 s390 处理器上的行为的 C++ 代码。

2. **寄存器操作:** 代码中使用了 `get_register(r)` 和 `set_register(r, value)` 函数来读取和写入通用寄存器的值（通常是 64 位的）。同时，也存在 `get_low_register<T>(r)` 和 `set_low_register(r, value)` 用于操作 32 位寄存器的低半部分。

3. **内存访问:** 代码中使用了 `ReadDW(addr)`, `ReadW(addr)`, `ReadH(addr)`, `ReadB(addr)`, `ReadWU(addr)`, `ReadHU(addr)` 等函数来模拟从内存中读取不同大小的数据（Double Word, Word, Halfword, Byte，以及无符号版本）。 相应的，也有 `WriteDW`, `WriteW`, `WriteH`, `WriteB` 等函数用于模拟向内存写入数据。

4. **条件码和溢出标志处理:** 代码中包含了 `SetS390ConditionCode` 和 `SetS390OverflowCode` 函数，用于模拟 s390 处理器中条件码和溢出标志的设置。条件码用于表示指令执行结果的状态，溢出标志表示运算是否发生溢出。

5. **算术和逻辑运算模拟:**  该文件实现了各种算术运算（加法、减法、乘法、除法）和逻辑运算（与、或、异或）的模拟，包括带符号和无符号的版本，以及针对 32 位和 64 位数据的操作。

6. **移位操作模拟:**  实现了逻辑左移 (`SLLG`)、逻辑右移 (`SRLG`)、算术左移 (`SLAG`) 和算术右移 (`SRAG`) 的模拟。

7. **字节序反转:**  实现了 `ByteReverse` 函数，用于模拟字节序反转操作，这在跨平台或者处理网络数据时非常重要。

8. **未实现指令处理:**  对于一些尚未实现的指令，代码中使用了 `UNIMPLEMENTED()` 宏，表明这些指令当前没有具体的模拟逻辑。

**关于文件类型和 JavaScript 关系：**

*   **文件类型:**  `v8/src/execution/s390/simulator-s390.cc` 以 `.cc` 结尾，这表明它是一个 **C++ 源代码文件**，而不是 Torque (`.tq`) 文件。
*   **JavaScript 关系:** 该文件直接关系到 JavaScript 的功能。 V8 JavaScript 引擎需要在各种不同的处理器架构上运行。 为了在 s390 架构上运行，V8 需要一个能够模拟 s390 指令的组件，这就是 `simulator-s390.cc` 的作用。 当 JavaScript 代码执行到需要 CPU 指令层面操作时，V8 会使用这个模拟器来执行这些指令。

**JavaScript 示例：**

即使 `simulator-s390.cc` 是 C++ 代码，它模拟的指令最终会支持 JavaScript 的运行。 例如，一个简单的 JavaScript 加法操作 `a + b`，在底层可能会被编译成一系列的 s390 指令，其中就可能包含类似 `AGRK` 或 `ARK` 这样的指令。

```javascript
let a = 10;
let b = 5;
let sum = a + b; // 这行 JavaScript 代码在底层可能涉及到类似 AGRK 指令的执行
console.log(sum); // 输出 15
```

在这个例子中，`a + b` 的加法运算最终需要在 s390 架构上执行。  `simulator-s390.cc` 中 `EVALUATE(AGRK)` 或 `EVALUATE(ARK)` 的代码就负责模拟这个加法操作。

**代码逻辑推理示例：**

假设我们执行以下 s390 指令，对应 `EVALUATE(AGRK)` 的模拟：

**假设输入：**

*   寄存器 `r2` 的值为 `5` (int64_t)
*   寄存器 `r3` 的值为 `10` (int64_t)
*   指令为 `AGRK r1, r2, r3`

**代码逻辑推理：**

1. `get_register(r2)` 获取 `r2` 的值，得到 `5`。
2. `get_register(r3)` 获取 `r3` 的值，得到 `10`。
3. `CheckOverflowForIntAdd(5, 10, int64_t)` 检查加法是否溢出。 在这个例子中，`5 + 10` 不会溢出，所以 `isOF` 为 `false`。
4. `SetS390ConditionCode<int64_t>(5 + 10, 0)` 设置条件码。结果 `15` 大于 `0`，条件码会根据 s390 的规则设置。
5. `SetS390OverflowCode(false)` 设置溢出标志为 `false`。
6. `set_register(r1, 5 + 10)` 将 `15` 写入寄存器 `r1`。

**输出：**

*   寄存器 `r1` 的值为 `15`。
*   条件码被设置为表示正数的结果。
*   溢出标志为 `false`。

**用户常见的编程错误示例：**

在模拟器层面，用户不会直接编写这里的 C++ 代码。但是，模拟器需要正确处理各种情况，包括用户在编写 JavaScript 代码时可能导致的错误，例如 **整数溢出**。

```javascript
let maxInt = 2147483647; // 32位有符号整数的最大值
let result = maxInt + 1;
console.log(result); // 在 JavaScript 中会输出 2147483648，但在某些底层运算中可能发生溢出
```

在上面的 JavaScript 例子中，如果底层的 s390 指令（例如 `ARK`，针对 32 位整数的加法）被用于执行 `maxInt + 1`，并且没有正确处理溢出，那么结果可能不是预期的。 `simulator-s390.cc` 中的 `CheckOverflowForIntAdd` 函数就是用来检测这种溢出的。 如果检测到溢出，`SetS390OverflowCode` 会被设置，V8 引擎可以根据这个标志来处理错误或采取其他措施。

**第 9 部分功能归纳：**

作为第 9 部分，这个代码片段主要集中在 **模拟 s390 架构的算术运算、逻辑运算、加载和存储指令**。  它涵盖了 64 位和 32 位整数的加法、减法、乘法、除法，以及位运算（AND、OR、XOR）。 此外，还包含了从内存加载数据到寄存器以及将寄存器数据存储到内存的指令模拟。  这部分代码是 s390 模拟器核心功能的关键组成部分，使得 V8 引擎能够在 s390 架构上执行 JavaScript 代码。

Prompt: 
```
这是目录为v8/src/execution/s390/simulator-s390.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/s390/simulator-s390.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第9部分，共10部分，请归纳一下它的功能

"""
CODE_RRF_A_INSTRUCTION(r1, r2, r3);
  // 64-bit Non-clobbering arithmetics / bitwise ops.
  int64_t r2_val = get_register(r2);
  int64_t r3_val = get_register(r3);
  bool isOF = CheckOverflowForIntAdd(r2_val, r3_val, int64_t);
  SetS390ConditionCode<int64_t>(r2_val + r3_val, 0);
  SetS390OverflowCode(isOF);
  set_register(r1, r2_val + r3_val);
  return length;
}

EVALUATE(SGRK) {
  DCHECK_OPCODE(SGRK);
  DECODE_RRF_A_INSTRUCTION(r1, r2, r3);
  // 64-bit Non-clobbering arithmetics / bitwise ops.
  int64_t r2_val = get_register(r2);
  int64_t r3_val = get_register(r3);
  bool isOF = CheckOverflowForIntSub(r2_val, r3_val, int64_t);
  SetS390ConditionCode<int64_t>(r2_val - r3_val, 0);
  SetS390OverflowCode(isOF);
  set_register(r1, r2_val - r3_val);
  return length;
}

EVALUATE(ALGRK) {
  DCHECK_OPCODE(ALGRK);
  DECODE_RRF_A_INSTRUCTION(r1, r2, r3);
  // 64-bit Non-clobbering unsigned arithmetics
  uint64_t r2_val = get_register(r2);
  uint64_t r3_val = get_register(r3);
  bool isOF = CheckOverflowForUIntAdd(r2_val, r3_val);
  SetS390ConditionCode<uint64_t>(r2_val + r3_val, 0);
  SetS390OverflowCode(isOF);
  set_register(r1, r2_val + r3_val);
  return length;
}

EVALUATE(SLGRK) {
  DCHECK_OPCODE(SLGRK);
  DECODE_RRF_A_INSTRUCTION(r1, r2, r3);
  // 64-bit Non-clobbering unsigned arithmetics
  uint64_t r2_val = get_register(r2);
  uint64_t r3_val = get_register(r3);
  bool isOF = CheckOverflowForUIntSub(r2_val, r3_val);
  SetS390ConditionCode<uint64_t>(r2_val - r3_val, 0);
  SetS390OverflowCode(isOF);
  set_register(r1, r2_val - r3_val);
  return length;
}

EVALUATE(LOCR) {
  DCHECK_OPCODE(LOCR);
  DECODE_RRF_C_INSTRUCTION(r1, r2, m3);
  if (TestConditionCode(m3)) {
    set_low_register(r1, get_low_register<int32_t>(r2));
  }
  return length;
}

EVALUATE(NRK) {
  DCHECK_OPCODE(NRK);
  DECODE_RRF_A_INSTRUCTION(r1, r2, r3);
  // 32-bit Non-clobbering arithmetics / bitwise ops
  int32_t r2_val = get_low_register<int32_t>(r2);
  int32_t r3_val = get_low_register<int32_t>(r3);
  // Assume bitwise operation here
  uint32_t bitwise_result = 0;
  bitwise_result = r2_val & r3_val;
  SetS390BitWiseConditionCode<uint32_t>(bitwise_result);
  set_low_register(r1, bitwise_result);
  return length;
}

EVALUATE(ORK) {
  DCHECK_OPCODE(ORK);
  DECODE_RRF_A_INSTRUCTION(r1, r2, r3);
  // 32-bit Non-clobbering arithmetics / bitwise ops
  int32_t r2_val = get_low_register<int32_t>(r2);
  int32_t r3_val = get_low_register<int32_t>(r3);
  // Assume bitwise operation here
  uint32_t bitwise_result = 0;
  bitwise_result = r2_val | r3_val;
  SetS390BitWiseConditionCode<uint32_t>(bitwise_result);
  set_low_register(r1, bitwise_result);
  return length;
}

EVALUATE(XRK) {
  DCHECK_OPCODE(XRK);
  DECODE_RRF_A_INSTRUCTION(r1, r2, r3);
  // 32-bit Non-clobbering arithmetics / bitwise ops
  int32_t r2_val = get_low_register<int32_t>(r2);
  int32_t r3_val = get_low_register<int32_t>(r3);
  // Assume bitwise operation here
  uint32_t bitwise_result = 0;
  bitwise_result = r2_val ^ r3_val;
  SetS390BitWiseConditionCode<uint32_t>(bitwise_result);
  set_low_register(r1, bitwise_result);
  return length;
}

EVALUATE(ARK) {
  DCHECK_OPCODE(ARK);
  DECODE_RRF_A_INSTRUCTION(r1, r2, r3);
  // 32-bit Non-clobbering arithmetics / bitwise ops
  int32_t r2_val = get_low_register<int32_t>(r2);
  int32_t r3_val = get_low_register<int32_t>(r3);
  bool isOF = CheckOverflowForIntAdd(r2_val, r3_val, int32_t);
  SetS390ConditionCode<int32_t>(r2_val + r3_val, 0);
  SetS390OverflowCode(isOF);
  set_low_register(r1, r2_val + r3_val);
  return length;
}

EVALUATE(SRK) {
  DCHECK_OPCODE(SRK);
  DECODE_RRF_A_INSTRUCTION(r1, r2, r3);
  // 32-bit Non-clobbering arithmetics / bitwise ops
  int32_t r2_val = get_low_register<int32_t>(r2);
  int32_t r3_val = get_low_register<int32_t>(r3);
  bool isOF = CheckOverflowForIntSub(r2_val, r3_val, int32_t);
  SetS390ConditionCode<int32_t>(r2_val - r3_val, 0);
  SetS390OverflowCode(isOF);
  set_low_register(r1, r2_val - r3_val);
  return length;
}

EVALUATE(ALRK) {
  DCHECK_OPCODE(ALRK);
  DECODE_RRF_A_INSTRUCTION(r1, r2, r3);
  // 32-bit Non-clobbering unsigned arithmetics
  uint32_t r2_val = get_low_register<uint32_t>(r2);
  uint32_t r3_val = get_low_register<uint32_t>(r3);
  bool isOF = CheckOverflowForUIntAdd(r2_val, r3_val);
  SetS390ConditionCode<uint32_t>(r2_val + r3_val, 0);
  SetS390OverflowCode(isOF);
  set_low_register(r1, r2_val + r3_val);
  return length;
}

EVALUATE(SLRK) {
  DCHECK_OPCODE(SLRK);
  DECODE_RRF_A_INSTRUCTION(r1, r2, r3);
  // 32-bit Non-clobbering unsigned arithmetics
  uint32_t r2_val = get_low_register<uint32_t>(r2);
  uint32_t r3_val = get_low_register<uint32_t>(r3);
  bool isOF = CheckOverflowForUIntSub(r2_val, r3_val);
  SetS390ConditionCode<uint32_t>(r2_val - r3_val, 0);
  SetS390OverflowCode(isOF);
  set_low_register(r1, r2_val - r3_val);
  return length;
}

EVALUATE(LTG) {
  DCHECK_OPCODE(LTG);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  intptr_t addr = x2_val + b2_val + d2;
  int64_t value = ReadDW(addr);
  set_register(r1, value);
  SetS390ConditionCode<int64_t>(value, 0);
  return length;
}

EVALUATE(CVBY) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(AG) {
  DCHECK_OPCODE(AG);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t alu_out = get_register(r1);
  int64_t mem_val = ReadDW(b2_val + x2_val + d2);
  bool isOF = CheckOverflowForIntAdd(alu_out, mem_val, int64_t);
  alu_out += mem_val;
  SetS390ConditionCode<int64_t>(alu_out, 0);
  SetS390OverflowCode(isOF);
  set_register(r1, alu_out);
  return length;
}

EVALUATE(SG) {
  DCHECK_OPCODE(SG);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t alu_out = get_register(r1);
  int64_t mem_val = ReadDW(b2_val + x2_val + d2);
  bool isOF = CheckOverflowForIntSub(alu_out, mem_val, int64_t);
  alu_out -= mem_val;
  SetS390ConditionCode<int32_t>(alu_out, 0);
  SetS390OverflowCode(isOF);
  set_register(r1, alu_out);
  return length;
}

EVALUATE(ALG) {
  DCHECK_OPCODE(ALG);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  uint64_t r1_val = get_register(r1);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  intptr_t d2_val = d2;
  uint64_t alu_out = r1_val;
  uint64_t mem_val = static_cast<uint64_t>(ReadDW(b2_val + d2_val + x2_val));
  alu_out += mem_val;
  SetS390ConditionCode<uint64_t>(alu_out, 0);
  set_register(r1, alu_out);
  return length;
}

EVALUATE(SLG) {
  DCHECK_OPCODE(SLG);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  uint64_t r1_val = get_register(r1);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  intptr_t d2_val = d2;
  uint64_t alu_out = r1_val;
  uint64_t mem_val = static_cast<uint64_t>(ReadDW(b2_val + d2_val + x2_val));
  alu_out -= mem_val;
  SetS390ConditionCode<uint64_t>(alu_out, 0);
  set_register(r1, alu_out);
  return length;
}

EVALUATE(MSG) {
  DCHECK_OPCODE(MSG);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  intptr_t d2_val = d2;
  int64_t mem_val = ReadDW(b2_val + d2_val + x2_val);
  int64_t r1_val = get_register(r1);
  set_register(r1, mem_val * r1_val);
  return length;
}

EVALUATE(DSG) {
  DCHECK_OPCODE(DSG);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  DCHECK_EQ(r1 % 2, 0);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  intptr_t d2_val = d2;
  int64_t mem_val = ReadDW(b2_val + d2_val + x2_val);
  int64_t r1_val = get_register(r1 + 1);
  int64_t quotient = r1_val / mem_val;
  int64_t remainder = r1_val % mem_val;
  set_register(r1, remainder);
  set_register(r1 + 1, quotient);
  return length;
}

EVALUATE(CVBG) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LT) {
  DCHECK_OPCODE(LT);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  intptr_t addr = x2_val + b2_val + d2;
  int32_t value = ReadW(addr);
  set_low_register(r1, value);
  SetS390ConditionCode<int32_t>(value, 0);
  return length;
}

EVALUATE(LGH) {
  DCHECK_OPCODE(LGH);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  // Miscellaneous Loads and Stores
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  intptr_t addr = x2_val + b2_val + d2;
  int64_t mem_val = static_cast<int64_t>(ReadH(addr));
  set_register(r1, mem_val);
  return length;
}

EVALUATE(LLGF) {
  DCHECK_OPCODE(LLGF);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  // Miscellaneous Loads and Stores
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  intptr_t addr = x2_val + b2_val + d2;
  uint64_t mem_val = static_cast<uint64_t>(ReadWU(addr));
  set_register(r1, mem_val);
  return length;
}

EVALUATE(LLGT) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(AGF) {
  DCHECK_OPCODE(AGF);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  uint64_t r1_val = get_register(r1);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  intptr_t d2_val = d2;
  uint64_t alu_out = r1_val;
  uint32_t mem_val = ReadW(b2_val + d2_val + x2_val);
  alu_out += mem_val;
  SetS390ConditionCode<int64_t>(alu_out, 0);
  set_register(r1, alu_out);
  return length;
}

EVALUATE(SGF) {
  DCHECK_OPCODE(SGF);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  uint64_t r1_val = get_register(r1);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  intptr_t d2_val = d2;
  uint64_t alu_out = r1_val;
  uint32_t mem_val = ReadW(b2_val + d2_val + x2_val);
  alu_out -= mem_val;
  SetS390ConditionCode<int64_t>(alu_out, 0);
  set_register(r1, alu_out);
  return length;
}

EVALUATE(ALGF) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SLGF) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(MSGF) {
  DCHECK_OPCODE(MSGF);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  intptr_t d2_val = d2;
  int64_t mem_val = static_cast<int64_t>(ReadW(b2_val + d2_val + x2_val));
  int64_t r1_val = get_register(r1);
  int64_t product = r1_val * mem_val;
  set_register(r1, product);
  return length;
}

EVALUATE(DSGF) {
  DCHECK_OPCODE(DSGF);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  DCHECK_EQ(r1 % 2, 0);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  intptr_t d2_val = d2;
  int64_t mem_val = static_cast<int64_t>(ReadW(b2_val + d2_val + x2_val));
  int64_t r1_val = get_register(r1 + 1);
  int64_t quotient = r1_val / mem_val;
  int64_t remainder = r1_val % mem_val;
  set_register(r1, remainder);
  set_register(r1 + 1, quotient);
  return length;
}

EVALUATE(LRVG) {
  DCHECK_OPCODE(LRVG);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  intptr_t mem_addr = b2_val + x2_val + d2;
  int64_t mem_val = ReadW64(mem_addr);
  set_register(r1, ByteReverse<int64_t>(mem_val));
  return length;
}

EVALUATE(LRV) {
  DCHECK_OPCODE(LRV);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  intptr_t mem_addr = b2_val + x2_val + d2;
  int32_t mem_val = ReadW(mem_addr);
  set_low_register(r1, ByteReverse<int32_t>(mem_val));
  return length;
}

EVALUATE(LRVH) {
  DCHECK_OPCODE(LRVH);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  int32_t r1_val = get_low_register<int32_t>(r1);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  intptr_t mem_addr = b2_val + x2_val + d2;
  int16_t mem_val = ReadH(mem_addr);
  int32_t result = ByteReverse<int16_t>(mem_val) & 0x0000FFFF;
  result |= r1_val & 0xFFFF0000;
  set_low_register(r1, result);
  return length;
}

EVALUATE(CG) {
  DCHECK_OPCODE(CG);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t alu_out = get_register(r1);
  int64_t mem_val = ReadDW(b2_val + x2_val + d2);
  SetS390ConditionCode<int64_t>(alu_out, mem_val);
  set_register(r1, alu_out);
  return length;
}

EVALUATE(CLG) {
  DCHECK_OPCODE(CLG);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t alu_out = get_register(r1);
  int64_t mem_val = ReadDW(b2_val + x2_val + d2);
  SetS390ConditionCode<uint64_t>(alu_out, mem_val);
  set_register(r1, alu_out);
  return length;
}

EVALUATE(NTSTG) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CVDY) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CVDG) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CGF) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CLGF) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LTGF) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CGH) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(PFD) {
  DCHECK_OPCODE(PFD);
  USE(instr);
  return 6;
}

EVALUATE(STRV) {
  DCHECK_OPCODE(STRV);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  int32_t r1_val = get_low_register<int32_t>(r1);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  intptr_t mem_addr = b2_val + x2_val + d2;
  WriteW(mem_addr, ByteReverse<int32_t>(r1_val));
  return length;
}

EVALUATE(STRVG) {
  DCHECK_OPCODE(STRVG);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  int64_t r1_val = get_register(r1);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  intptr_t mem_addr = b2_val + x2_val + d2;
  WriteDW(mem_addr, ByteReverse<int64_t>(r1_val));
  return length;
}

EVALUATE(STRVH) {
  DCHECK_OPCODE(STRVH);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  int32_t r1_val = get_low_register<int32_t>(r1);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  intptr_t mem_addr = b2_val + x2_val + d2;
  int16_t result = static_cast<int16_t>(r1_val >> 16);
  WriteH(mem_addr, ByteReverse<int16_t>(result));
  return length;
}

EVALUATE(BCTG) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(MSY) {
  DCHECK_OPCODE(MSY);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  intptr_t d2_val = d2;
  int32_t mem_val = ReadW(b2_val + d2_val + x2_val);
  int32_t r1_val = get_low_register<int32_t>(r1);
  set_low_register(r1, mem_val * r1_val);
  return length;
}

EVALUATE(MSC) {
  DCHECK_OPCODE(MSC);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  intptr_t d2_val = d2;
  int32_t mem_val = ReadW(b2_val + d2_val + x2_val);
  int32_t r1_val = get_low_register<int32_t>(r1);
  int64_t result64 =
      static_cast<int64_t>(r1_val) * static_cast<int64_t>(mem_val);
  int32_t result32 = static_cast<int32_t>(result64);
  bool isOF = (static_cast<int64_t>(result32) != result64);
  SetS390ConditionCode<int32_t>(result32, 0);
  SetS390OverflowCode(isOF);
  set_low_register(r1, result32);
  set_low_register(r1, mem_val * r1_val);
  return length;
}

EVALUATE(NY) {
  DCHECK_OPCODE(NY);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int32_t alu_out = get_low_register<int32_t>(r1);
  int32_t mem_val = ReadW(b2_val + x2_val + d2);
  alu_out &= mem_val;
  SetS390BitWiseConditionCode<uint32_t>(alu_out);
  set_low_register(r1, alu_out);
  return length;
}

EVALUATE(CLY) {
  DCHECK_OPCODE(CLY);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  uint32_t alu_out = get_low_register<uint32_t>(r1);
  uint32_t mem_val = ReadWU(b2_val + x2_val + d2);
  SetS390ConditionCode<uint32_t>(alu_out, mem_val);
  return length;
}

EVALUATE(OY) {
  DCHECK_OPCODE(OY);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int32_t alu_out = get_low_register<int32_t>(r1);
  int32_t mem_val = ReadW(b2_val + x2_val + d2);
  alu_out |= mem_val;
  SetS390BitWiseConditionCode<uint32_t>(alu_out);
  set_low_register(r1, alu_out);
  return length;
}

EVALUATE(XY) {
  DCHECK_OPCODE(XY);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int32_t alu_out = get_low_register<int32_t>(r1);
  int32_t mem_val = ReadW(b2_val + x2_val + d2);
  alu_out ^= mem_val;
  SetS390BitWiseConditionCode<uint32_t>(alu_out);
  set_low_register(r1, alu_out);
  return length;
}

EVALUATE(CY) {
  DCHECK_OPCODE(CY);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int32_t alu_out = get_low_register<int32_t>(r1);
  int32_t mem_val = ReadW(b2_val + x2_val + d2);
  SetS390ConditionCode<int32_t>(alu_out, mem_val);
  return length;
}

EVALUATE(AY) {
  DCHECK_OPCODE(AY);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int32_t alu_out = get_low_register<int32_t>(r1);
  int32_t mem_val = ReadW(b2_val + x2_val + d2);
  bool isOF = false;
  isOF = CheckOverflowForIntAdd(alu_out, mem_val, int32_t);
  alu_out += mem_val;
  SetS390ConditionCode<int32_t>(alu_out, 0);
  SetS390OverflowCode(isOF);
  set_low_register(r1, alu_out);
  return length;
}

EVALUATE(SY) {
  DCHECK_OPCODE(SY);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int32_t alu_out = get_low_register<int32_t>(r1);
  int32_t mem_val = ReadW(b2_val + x2_val + d2);
  bool isOF = false;
  isOF = CheckOverflowForIntSub(alu_out, mem_val, int32_t);
  alu_out -= mem_val;
  SetS390ConditionCode<int32_t>(alu_out, 0);
  SetS390OverflowCode(isOF);
  set_low_register(r1, alu_out);
  return length;
}

EVALUATE(MFY) {
  DCHECK_OPCODE(MFY);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  DCHECK_EQ(r1 % 2, 0);
  int32_t mem_val = ReadW(b2_val + x2_val + d2);
  int32_t r1_val = get_low_register<int32_t>(r1 + 1);
  int64_t product =
      static_cast<int64_t>(r1_val) * static_cast<int64_t>(mem_val);
  int32_t high_bits = product >> 32;
  r1_val = high_bits;
  int32_t low_bits = product & 0x00000000FFFFFFFF;
  set_low_register(r1, high_bits);
  set_low_register(r1 + 1, low_bits);
  return length;
}

EVALUATE(ALY) {
  DCHECK_OPCODE(ALY);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  uint32_t alu_out = get_low_register<uint32_t>(r1);
  uint32_t mem_val = ReadWU(b2_val + x2_val + d2);
  alu_out += mem_val;
  set_low_register(r1, alu_out);
  SetS390ConditionCode<uint32_t>(alu_out, 0);
  return length;
}

EVALUATE(SLY) {
  DCHECK_OPCODE(SLY);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  uint32_t alu_out = get_low_register<uint32_t>(r1);
  uint32_t mem_val = ReadWU(b2_val + x2_val + d2);
  alu_out -= mem_val;
  set_low_register(r1, alu_out);
  SetS390ConditionCode<uint32_t>(alu_out, 0);
  return length;
}

EVALUATE(STHY) {
  DCHECK_OPCODE(STHY);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  // Miscellaneous Loads and Stores
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  intptr_t addr = x2_val + b2_val + d2;
  uint16_t value = get_low_register<uint32_t>(r1);
  WriteH(addr, value);
  return length;
}

EVALUATE(LAY) {
  DCHECK_OPCODE(LAY);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  // Load Address
  int rb = b2;
  int rx = x2;
  int offset = d2;
  int64_t rb_val = (rb == 0) ? 0 : get_register(rb);
  int64_t rx_val = (rx == 0) ? 0 : get_register(rx);
  set_register(r1, rx_val + rb_val + offset);
  return length;
}

EVALUATE(STCY) {
  DCHECK_OPCODE(STCY);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  // Miscellaneous Loads and Stores
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  intptr_t addr = x2_val + b2_val + d2;
  uint8_t value = get_low_register<uint32_t>(r1);
  WriteB(addr, value);
  return length;
}

EVALUATE(ICY) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LAEY) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LB) {
  DCHECK_OPCODE(LB);
  // Miscellaneous Loads and Stores
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  intptr_t addr = x2_val + b2_val + d2;
  int32_t mem_val = ReadB(addr);
  set_low_register(r1, mem_val);
  return length;
}

EVALUATE(LGB) {
  DCHECK_OPCODE(LGB);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  // Miscellaneous Loads and Stores
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  intptr_t addr = x2_val + b2_val + d2;
  int64_t mem_val = ReadB(addr);
  set_register(r1, mem_val);
  return length;
}

EVALUATE(LHY) {
  DCHECK_OPCODE(LHY);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  // Miscellaneous Loads and Stores
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  intptr_t addr = x2_val + b2_val + d2;
  int32_t result = static_cast<int32_t>(ReadH(addr));
  set_low_register(r1, result);
  return length;
}

EVALUATE(CHY) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(AHY) {
  DCHECK_OPCODE(AHY);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  int32_t r1_val = get_low_register<int32_t>(r1);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  intptr_t d2_val = d2;
  int32_t mem_val = static_cast<int32_t>(ReadH(b2_val + d2_val + x2_val));
  int32_t alu_out = 0;
  bool isOF = false;
  alu_out = r1_val + mem_val;
  isOF = CheckOverflowForIntAdd(r1_val, mem_val, int32_t);
  set_low_register(r1, alu_out);
  SetS390ConditionCode<int32_t>(alu_out, 0);
  SetS390OverflowCode(isOF);
  return length;
}

EVALUATE(SHY) {
  DCHECK_OPCODE(SHY);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  int32_t r1_val = get_low_register<int32_t>(r1);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  intptr_t d2_val = d2;
  int32_t mem_val = static_cast<int32_t>(ReadH(b2_val + d2_val + x2_val));
  int32_t alu_out = 0;
  bool isOF = false;
  alu_out = r1_val - mem_val;
  isOF = CheckOverflowForIntSub(r1_val, mem_val, int64_t);
  set_low_register(r1, alu_out);
  SetS390ConditionCode<int32_t>(alu_out, 0);
  SetS390OverflowCode(isOF);
  return length;
}

EVALUATE(MHY) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(NG) {
  DCHECK_OPCODE(NG);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t alu_out = get_register(r1);
  int64_t mem_val = ReadDW(b2_val + x2_val + d2);
  alu_out &= mem_val;
  SetS390BitWiseConditionCode<uint32_t>(alu_out);
  set_register(r1, alu_out);
  return length;
}

EVALUATE(OG) {
  DCHECK_OPCODE(OG);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t alu_out = get_register(r1);
  int64_t mem_val = ReadDW(b2_val + x2_val + d2);
  alu_out |= mem_val;
  SetS390BitWiseConditionCode<uint32_t>(alu_out);
  set_register(r1, alu_out);
  return length;
}

EVALUATE(XG) {
  DCHECK_OPCODE(XG);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t alu_out = get_register(r1);
  int64_t mem_val = ReadDW(b2_val + x2_val + d2);
  alu_out ^= mem_val;
  SetS390BitWiseConditionCode<uint32_t>(alu_out);
  set_register(r1, alu_out);
  return length;
}

EVALUATE(LGAT) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(DLG) {
  DCHECK_OPCODE(DLG);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  uint64_t r1_val = get_register(r1);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  DCHECK_EQ(r1 % 2, 0);
  unsigned __int128 dividend = static_cast<unsigned __int128>(r1_val) << 64;
  dividend += get_register(r1 + 1);
  int64_t mem_val = ReadDW(b2_val + x2_val + d2);
  uint64_t remainder = dividend % mem_val;
  uint64_t quotient = dividend / mem_val;
  set_register(r1, remainder);
  set_register(r1 + 1, quotient);
  return length;
}

EVALUATE(ALCG) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SLBG) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(STPQ) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LPQ) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LLGH) {
  DCHECK_OPCODE(LLGH);
  // Load Logical Halfword
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  intptr_t d2_val = d2;
  uint16_t mem_val = ReadHU(b2_val + d2_val + x2_val);
  set_register(r1, mem_val);
  return length;
}

EVALUATE(LLH) {
  DCHECK_OPCODE(LLH);
  // Load Logical Halfword
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  intptr_t d2_val = d2;
  uint16_t mem_val = ReadHU(b2_val + d2_val + x2_val);
  set_low_register(r1, mem_val);
  return length;
}

EVALUATE(ML) {
  DCHECK_OPCODE(ML);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  DCHECK_EQ(r1 % 2, 0);
  uint32_t mem_val = ReadWU(b2_val + x2_val + d2);
  uint32_t r1_val = get_low_register<uint32_t>(r1 + 1);
  uint64_t product =
      static_cast<uint64_t>(r1_val) * static_cast<uint64_t>(mem_val);
  uint32_t high_bits = product >> 32;
  r1_val = high_bits;
  uint32_t low_bits = product & 0x00000000FFFFFFFF;
  set_low_register(r1, high_bits);
  set_low_register(r1 + 1, low_bits);
  return length;
}

EVALUATE(DL) {
  DCHECK_OPCODE(DL);
  DECODE_RXY_A_INSTRUCTION(r1, x2, b2, d2);
  int64_t x2_val = (x2 == 0) ? 0 : get_register(x2);
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  DCHECK_EQ(r1 % 2, 0);
  uint32_t mem_val = ReadWU(b2_val + x2_val + d2);
  uint32_t r1_val = get_low_register<uint32_t>(r1 + 1);
  uint64_t quotient =
      static_cast<uint64_t>(r1_val) / static_cast<uint64_t>(mem_val);
  uint64_t remainder =
      static_cast<uint64_t>(r1_val) % static_cast<uint64_t>(mem_val);
  set_low_register(r1, remainder);
  set_low_register(r1 + 1, quotient);
  return length;
}

EVALUATE(ALC) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SLB) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LLGTAT) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LLGFAT) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LAT) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LBH) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LLCH) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(STCH) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LHH) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LLHH) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(STHH) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LFHAT) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LFH) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(STFH) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CHF) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(MVCDK) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(MVHHI) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(MVGHI) {
  DCHECK_OPCODE(MVGHI);
  // Move Integer (64)
  DECODE_SIL_INSTRUCTION(b1, d1, i2);
  int64_t b1_val = (b1 == 0) ? 0 : get_register(b1);
  intptr_t src_addr = b1_val + d1;
  WriteDW(src_addr, i2);
  return length;
}

EVALUATE(MVHI) {
  DCHECK_OPCODE(MVHI);
  // Move Integer (32)
  DECODE_SIL_INSTRUCTION(b1, d1, i2);
  int64_t b1_val = (b1 == 0) ? 0 : get_register(b1);
  intptr_t src_addr = b1_val + d1;
  WriteW(src_addr, i2);
  return length;
}

EVALUATE(CHHSI) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CGHSI) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CHSI) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CLFHSI) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(TBEGIN) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(TBEGINC) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LMG) {
  DCHECK_OPCODE(LMG);
  // Store Multiple 64-bits.
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
    int64_t value = ReadDW(rb_val + offset + 8 * i);
    set_register((r1 + i) % 16, value);
  }
  return length;
}

EVALUATE(SRAG) {
  DCHECK_OPCODE(SRAG);
  // 64-bit non-clobbering shift-left/right arithmetic
  DECODE_RSY_A_INSTRUCTION(r1, r3, b2, d2);
  // only takes rightmost 6 bits
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int shiftBits = (b2_val + d2) & 0x3F;
  int64_t r3_val = get_register(r3);
  intptr_t alu_out = 0;
  bool isOF = false;
  alu_out = r3_val >> shiftBits;
  set_register(r1, alu_out);
  SetS390ConditionCode<intptr_t>(alu_out, 0);
  SetS390OverflowCode(isOF);
  return length;
}

EVALUATE(SLAG) {
  DCHECK_OPCODE(SLAG);
  // 64-bit non-clobbering shift-left/right arithmetic
  DECODE_RSY_A_INSTRUCTION(r1, r3, b2, d2);
  // only takes rightmost 6 bits
  int64_t b2_val = (b2 == 0) ? 0 : get_register(b2);
  int shiftBits = (b2_val + d2) & 0x3F;
  int64_t r3_val = get_register(r3);
  intptr_t alu_out = 0;
  bool isOF = false;
  isOF = CheckOverflowForShiftLeft(r3_val, shiftBits);
  alu_out = r3_val << shiftBits;
  set_register(r1, alu_out);
  SetS390ConditionCode<intptr_t>(alu_out, 0);
  SetS390OverflowCode(isOF);
  return length;
}

EVALUATE(SRLG) {
  DCHECK_OPCODE(SRLG);
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
  alu_out = r3_val >> shiftBits;
  set_register(r1, alu_out);
  return length;
}

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
  // unsigned
  uint64_t r3_val = get_register(r3);
  uint64_t alu_out = 0;
  alu_out = r3_v
"""


```