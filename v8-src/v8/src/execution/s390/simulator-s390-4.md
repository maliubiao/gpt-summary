Response: The user wants a summary of the functionality of the provided C++ code, which is part 5 of a larger file. The code seems to be implementing a simulator for the s390 architecture within the V8 JavaScript engine.

Here's a breakdown of the thought process:

1. **Identify the Context:** The file path `v8/src/execution/s390/simulator-s390.cc` immediately suggests that this code is part of the V8 JavaScript engine and is related to simulating the s390 architecture. The "part 5 of 5" confirms that this is the final section of a larger file dedicated to this simulator.

2. **Analyze the Code Structure:** The code consists of a series of `EVALUATE` blocks. Each block seems to correspond to a specific s390 instruction (e.g., `SGRK`, `ALGRK`, `LTG`, `AG`). The `DCHECK_OPCODE` macro likely verifies the correctness of the opcode being evaluated.

3. **Infer Instruction Semantics:**  Within each `EVALUATE` block, there are operations that manipulate registers (`get_register`, `set_register`, `get_low_register`, `set_low_register`), memory (`ReadDW`, `ReadW`, `WriteDW`, `WriteW`), and condition codes (`SetS390ConditionCode`, `SetS390OverflowCode`, `SetS390BitWiseConditionCode`). The names of the instructions (e.g., `AG` for Add, `SG` for Subtract, `LTG` for Load) provide strong hints about their functionality.

4. **Identify Core Functionality:**  The code simulates the execution of s390 instructions. This involves:
    * **Decoding instructions:** Extracting operands from the instruction format (using `DECODE_*_INSTRUCTION` macros).
    * **Fetching operands:** Reading register values and memory contents.
    * **Performing operations:** Executing the logic of the instruction (arithmetic, bitwise, load/store, comparisons, shifts, etc.).
    * **Updating state:** Writing results back to registers and memory, and setting condition codes.
    * **Returning length:** Indicating the size of the executed instruction.

5. **Relate to JavaScript:**  V8 is a JavaScript engine. This simulator is used when V8 needs to execute JavaScript code on an s390 architecture without relying on the actual hardware. The simulator translates s390 assembly instructions into actions that can be performed on the host machine's architecture.

6. **Construct the Summary:** Based on the analysis, formulate a concise summary highlighting the core purpose of the code: simulating s390 instructions within V8.

7. **Provide a JavaScript Example (if applicable):**  Consider how these simulated instructions relate to JavaScript features. Arithmetic operations, memory access, and comparisons in JavaScript directly translate to the kind of low-level operations being simulated. A simple JavaScript arithmetic expression like `let a = b + c;` would involve loading values (simulated by `LTG`, `LGH`, etc.), performing addition (simulated by `AG`, `ARK`, etc.), and storing the result (simulated by `STG`, `ST`).

8. **Refine and Review:** Ensure the summary is accurate, clear, and addresses all aspects of the prompt. Specifically, confirm the "part 5" aspect is included.

Self-Correction/Refinement during the process:

* Initially, I might have focused too much on the individual instruction implementations. The key is to generalize and identify the overall function.
* I might have overlooked the connection to JavaScript. It's important to explicitly state why this simulator is relevant to V8.
* I needed to ensure the JavaScript example was simple and clearly illustrated the link between high-level JavaScript and the low-level simulated instructions.
Based on the provided C++ code snippet from `v8/src/execution/s390/simulator-s390.cc`, part 5 of 5, its primary function is to **simulate the execution of various s390 instructions within the V8 JavaScript engine**.

Here's a breakdown of its functionality:

* **Instruction Simulation:** The code defines a series of `EVALUATE` blocks. Each `EVALUATE` block corresponds to a specific s390 assembly instruction (e.g., `SGRK`, `ALGRK`, `LTG`, `AG`).
* **Decoding Instructions:**  Macros like `DECODE_RRF_A_INSTRUCTION`, `DECODE_RXY_A_INSTRUCTION`, etc., are used to parse the raw instruction bytes and extract the operands (registers, immediate values, memory addresses).
* **Register and Memory Access:**  Functions like `get_register`, `set_register`, `get_low_register`, `set_low_register`, `ReadDW`, `ReadW`, `WriteDW`, `WriteW`, etc., are used to simulate the reading and writing of data to the s390's general-purpose registers and memory.
* **Arithmetic and Logical Operations:**  The code implements the logic for various arithmetic operations (addition, subtraction, multiplication, division), logical operations (AND, OR, XOR), and bitwise shifts, mirroring the behavior of the corresponding s390 instructions.
* **Condition Code and Overflow Handling:**  Functions like `SetS390ConditionCode`, `SetS390OverflowCode`, and `SetS390BitWiseConditionCode` are used to simulate the setting of the s390 processor's condition codes and overflow flags based on the results of the simulated instructions.
* **Control Flow Instructions (Indirectly):** While the provided snippet doesn't show explicit control flow instructions like branches, the simulation of condition codes is crucial for their correct behavior in other parts of the simulator.
* **Floating-Point Instruction Simulation:**  The presence of instructions like `LDEB`, `CEB`, `AEB`, `SDB`, etc., indicates the simulation of floating-point operations and the use of floating-point registers (`get_fpr`, `set_fpr`).
* **Atomic Operations:** Instructions like `LANG`, `LAOG`, `LAN`, `LAO`, etc., suggest the simulation of atomic memory operations using functions like `__atomic_fetch_and`, `__atomic_fetch_or`, etc.

**Relationship to JavaScript and Example:**

This code is part of V8's infrastructure to run JavaScript code on s390 architectures. When V8 needs to execute JavaScript on an s390 system, and either a native implementation for that specific instruction is not available or for debugging/testing purposes, the simulator steps in. It interprets the s390 machine code generated by V8's compiler and executes it instruction by instruction.

Here's a simplified conceptual example in JavaScript of how the simulated s390 instructions might relate to JavaScript operations:

```javascript
// Hypothetical JavaScript code
let a = 10;
let b = 5;
let sum = a + b;
```

When this JavaScript code is compiled by V8 for an s390 architecture, it might be translated into a sequence of s390 instructions. The `simulator-s390.cc` code would then simulate these instructions. For instance:

1. **Loading values of `a` and `b` into registers:** This might involve simulating instructions like `L` (Load) or `LG` (Load and Extend) to fetch the values from memory into s390 registers. The `EVALUATE(LT)` or `EVALUATE(LTG)` blocks in the C++ code would handle this.

   ```c++
   // Inside EVALUATE(LT) or EVALUATE(LTG)
   int32_t value = ReadW(address_of_a); // Simulate reading 'a' from memory
   set_low_register(register1, value);   // Simulate placing 'a' in a register

   int32_t value_b = ReadW(address_of_b); // Simulate reading 'b' from memory
   set_low_register(register2, value_b);   // Simulate placing 'b' in a register
   ```

2. **Performing the addition:** The JavaScript `+` operation would likely be translated into an s390 addition instruction like `ARK` (Add Register) for 32-bit integers or `AGRK` (Add Register) for 64-bit integers. The corresponding `EVALUATE(ARK)` or `EVALUATE(AGRK)` block would be executed by the simulator.

   ```c++
   // Inside EVALUATE(ARK)
   int32_t r2_val = get_low_register<int32_t>(register1); // Get the value of 'a'
   int32_t r3_val = get_low_register<int32_t>(register2); // Get the value of 'b'
   int32_t result = r2_val + r3_val;                    // Simulate the addition
   set_low_register(register3, result);                  // Simulate storing the sum in a register
   ```

3. **Storing the result `sum` back to memory:** This would involve simulating a store instruction like `ST` (Store) or `STG` (Store) using the `EVALUATE(STY)` or `EVALUATE(STGY)` blocks.

   ```c++
   // Inside EVALUATE(STY)
   int32_t value_to_store = get_low_register<int32_t>(register3); // Get the sum
   WriteW(address_of_sum, value_to_store);                      // Simulate writing the sum to memory
   ```

**In essence, this C++ code acts as a software implementation of the s390 architecture's instruction set, allowing V8 to execute JavaScript code on s390 systems without needing the actual hardware for testing or in environments where direct execution is not possible.** The "part 5 of 5" indicates that this is the final segment covering a significant portion of the s390 instruction set supported by the simulator.

Prompt: 
```
这是目录为v8/src/execution/s390/simulator-s390.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第5部分，共5部分，请归纳一下它的功能

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
  alu_out = r3_val << shiftBits;
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

"""


```