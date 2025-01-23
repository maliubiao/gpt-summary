Response: The user wants a summary of the provided C++ code, which is part 4 of 5 of a larger file. The code seems to be implementing a simulator for the s390 architecture, specifically the execution of various s390 instructions.

Here's a breakdown of how to arrive at the summary:

1. **Identify the context:** The code snippet is from `v8/src/execution/s390/simulator-s390.cc`. This clearly indicates it's part of the V8 JavaScript engine and is related to simulating s390 instructions.

2. **Analyze the structure:** The code consists of multiple `EVALUATE` macros. Each `EVALUATE` macro seems to be associated with a specific s390 instruction (e.g., `SRL`, `SLL`, `STM`, `MVC`, etc.). Inside each macro, there's code that decodes the instruction and then performs the corresponding operation on simulated registers and memory.

3. **Recognize the core functionality:** The primary purpose of this code is to interpret and execute s390 instructions within the V8 simulator. This involves fetching operands, performing the operation defined by the instruction, and updating the simulated CPU state (registers, memory, condition codes).

4. **Relate to JavaScript (if applicable):**  The prompt specifically asks about the relationship to JavaScript. Since this is part of V8, the simulator is used to run JavaScript code on s390 platforms. When V8 needs to execute JavaScript on an s390 architecture, and direct execution isn't possible (e.g., during JIT compilation or when running in an interpreter), this simulator is used to mimic the behavior of the s390 processor.

5. **Construct the summary:** Based on the above points, we can formulate a summary that highlights the core functionality: simulating s390 instructions.

6. **Provide a JavaScript example (if applicable):**  To illustrate the connection to JavaScript, a simple example showing how JavaScript code might eventually be translated into machine code (and therefore potentially simulated by this code) is useful. A basic arithmetic operation like `a + b` serves as a good example because it's a fundamental operation that corresponds to machine instructions. We can then show a simplified conceptual mapping to s390 instructions.

7. **Incorporate the "part 4 of 5" information:**  The prompt emphasizes that this is part 4 of 5. This suggests that this particular file handles a subset of the total s390 instruction set. The summary should include this detail.

8. **Refine the summary:** Review the summary for clarity, accuracy, and conciseness. Ensure it addresses all aspects of the prompt. For instance, explicitly mentioning the manipulation of registers and memory within the simulator enhances the summary.
Based on the provided C++ code snippet from `v8/src/execution/s390/simulator-s390.cc`, which is part 4 of 5, its primary function is to **implement the execution logic for a significant number of s390 instructions within the V8 simulator.**

This part specifically focuses on the implementation of various **arithmetic, logical, memory manipulation, branching, and floating-point instructions** for the s390 architecture. Each `EVALUATE` macro defines the behavior of a specific s390 instruction when the simulator encounters it.

Here's a breakdown of the types of instructions covered in this snippet:

* **Shift Instructions:** `SRL`, `SLL`, `SRA`, `SLA`, `SRDL`, `SLDL`, `SRDA` (Logical and Arithmetic shifts, single and double register versions).
* **Store/Load Multiple:** `STM`, `LM` (Storing and loading multiple registers to/from memory).
* **Immediate Operations:** `CLI`, `NILH`, `NILL`, `OILH`, `OILL`, `TMLH`, `TMLL`, `TMHH`, `TMHL`, `LHI`, `LGHI`, `MHI`, `MGHI`, `CHI`, `CGHI`, `XIHF`, `XILF`, `NIHF`, `NILF`, `OIHF`, `OILF`, `LLIHF`, `LLILF`, `MSGFI`, `MSFI`, `SLGFI`, `SLFI`, `AGFI`, `AFI`, `ALGFI`, `ALFI`, `CGFI`, `CFI`, `CLGFI`, `CLFI`, `AIH`, `CIH`, `CLIH` (Various operations with immediate values).
* **Branching:** `BRAS`, `BRCT`, `BRCTG`, `LARL`, `BRASL` (Conditional and unconditional branches, including relative addressing and saving the return address).
* **Logical Operations:** `NILH`, `NILL`, `OILH`, `OILL`, `XIHF`, `XILF`, `NIHF`, `NILF`, `OIHF`, `OILF`, `NGR`, `OGR`, `XGR`, `NGRK`, `OGRK`, `XGRK` (Bitwise AND, OR, XOR operations).
* **Move Instructions:** `MVC` (Move character data in memory).
* **Floating-Point Instructions:** A wide range of single and double-precision floating-point operations including `LPEBR`, `LTEBR`, `LCEBR`, `LDEBR`, `CEBR`, `AEBR`, `SEBR`, `DEBR`, `LPDBR`, `LTDBR`, `LCDBR`, `SQEBR`, `SQDBR`, `MEEBR`, `CDBR`, `ADBR`, `SDBR`, `MDBR`, `DDBR`, `MADBR`, `LEDBRA`, `LPGR`, `LNGR`, `LTGR`, `LCGR`, `SGR`, `ALGR`, `MSGR`, `DSGR`, `LPGFR`, `LTGFR`, `LCGFR`, `LLGFR`, `AGFR`, `SGFR`, `MSGFR`, `DSGFR`, `LPGR`, `LNGR`, `LTGR`, `LCGR`, `SGR`, `ALGR`, `MSGR`, `DSGR`, and many more. These handle loading, negation, comparison, arithmetic operations, and conversions for floating-point numbers.
* **Other Instructions:** Instructions like `TRAP4` (for triggering software interrupts), `MSR`, `MSRKC`, `POPCNT_Z`, `LOCGR`, `LLCR`, `LLHR`, `MLR`, `DLR`, `ALCR`, `SLBR`, `MGRK`, `MLGR`, `DLGR`, `LLGCR`, `LLGHR`.

**Relationship to JavaScript and Example:**

This code is crucial for V8's ability to execute JavaScript code on s390 architectures. When JavaScript code is compiled (either just-in-time or ahead-of-time) for s390, the resulting machine code consists of s390 instructions. If V8 needs to execute this code in a simulated environment (for example, if the underlying hardware is different or during debugging), this simulator, and specifically this part of it, interprets and executes those s390 instructions.

Here's a simplified illustration using a basic JavaScript addition:

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
console.log(result); // Output: 15
```

When V8 compiles this JavaScript code for s390, the `a + b` operation might be translated into an s390 **Add Register (AR)** instruction (or similar). The `EVALUATE(AR)` block (likely present in other parts of this file or adjacent files) would contain the C++ code that simulates what the actual s390 `AR` instruction does: reading the values of `a` and `b` from simulated registers, performing the addition, and storing the result back into a simulated register.

Similarly, more complex JavaScript operations would be translated into sequences of s390 instructions, and the corresponding `EVALUATE` blocks in the simulator would handle their execution. For instance, a JavaScript string manipulation might involve the `MVC` (Move Character) instruction, which is implemented in this snippet.

**In summary, this part of the `simulator-s390.cc` file provides the core instruction execution engine for the V8 JavaScript engine's s390 simulator, enabling it to run JavaScript code on s390 platforms even when direct hardware execution is not possible or desired.** The extensive list of `EVALUATE` macros in this snippet highlights the breadth of s390 instructions that this part of the simulator can handle.

### 提示词
```
这是目录为v8/src/execution/s390/simulator-s390.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```
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
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CDBR) {
  DCHECK_OPCODE(CDBR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  double r1_val = get_fpr<double>(r1);
  double r2_val = get_fpr<double>(r2);
  if (isNaN(r1_val) || isNaN(r2_val)) {
    condition_reg_ = CC_OF;
  } else {
    SetS390ConditionCode<double>(r1_val, r2_val);
  }
  return length;
}

EVALUATE(ADBR) {
  DCHECK_OPCODE(ADBR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  double r1_val = get_fpr<double>(r1);
  double r2_val = get_fpr<double>(r2);
  r1_val += r2_val;
  set_fpr(r1, r1_val);
  SetS390ConditionCode<double>(r1_val, 0);
  return length;
}

EVALUATE(SDBR) {
  DCHECK_OPCODE(SDBR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  double r1_val = get_fpr<double>(r1);
  double r2_val = get_fpr<double>(r2);
  r1_val -= r2_val;
  set_fpr(r1, r1_val);
  SetS390ConditionCode<double>(r1_val, 0);
  return length;
}

EVALUATE(MDBR) {
  DCHECK_OPCODE(MDBR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  double r1_val = get_fpr<double>(r1);
  double r2_val = get_fpr<double>(r2);
  r1_val *= r2_val;
  set_fpr(r1, r1_val);
  return length;
}

EVALUATE(DDBR) {
  DCHECK_OPCODE(DDBR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  double r1_val = get_fpr<double>(r1);
  double r2_val = get_fpr<double>(r2);
  r1_val /= r2_val;
  set_fpr(r1, r1_val);
  return length;
}

EVALUATE(MADBR) {
  DCHECK_OPCODE(MADBR);
  DECODE_RRD_INSTRUCTION(r1, r2, r3);
  double r1_val = get_fpr<double>(r1);
  double r2_val = get_fpr<double>(r2);
  double r3_val = get_fpr<double>(r3);
  r1_val += r2_val * r3_val;
  set_fpr(r1, r1_val);
  SetS390ConditionCode<double>(r1_val, 0);
  return length;
}

EVALUATE(MSDBR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LPXBR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LNXBR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LTXBR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LCXBR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LEDBRA) {
  DCHECK_OPCODE(LEDBRA);
  DECODE_RRE_INSTRUCTION(r1, r2);
  double r2_val = get_fpr<double>(r2);
  set_fpr(r1, static_cast<float>(r2_val));
  return length;
}

EVALUATE(LDXBRA) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LEXBRA) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(FIXBRA) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(KXBR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CXBR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(AXBR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SXBR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(MXBR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(DXBR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(TBEDR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(TBDR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(DIEBR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(THDER) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(THDR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(DIDBR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LXR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LPDFR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LNDFR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LCDFR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LZER) {
  DCHECK_OPCODE(LZER);
  DECODE_RRE_INSTRUCTION_NO_R2(r1);
  set_fpr<float>(r1, 0.0);
  return length;
}

EVALUATE(LZDR) {
  DCHECK_OPCODE(LZDR);
  DECODE_RRE_INSTRUCTION_NO_R2(r1);
  set_fpr<double>(r1, 0.0);
  return length;
}

EVALUATE(LZXR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SFPC) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SFASR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(EFPC) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CELFBR) {
  DCHECK_OPCODE(CELFBR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  uint32_t r2_val = get_low_register<uint32_t>(r2);
  float r1_val = static_cast<float>(r2_val);
  set_fpr(r1, r1_val);
  return length;
}

EVALUATE(CDLFBR) {
  DCHECK_OPCODE(CDLFBR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  uint32_t r2_val = get_low_register<uint32_t>(r2);
  double r1_val = static_cast<double>(r2_val);
  set_fpr(r1, r1_val);
  return length;
}

EVALUATE(CXLFBR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CEFBRA) {
  DCHECK_OPCODE(CEFBRA);
  DECODE_RRE_INSTRUCTION(r1, r2);
  int32_t fr2_val = get_low_register<int32_t>(r2);
  float fr1_val = static_cast<float>(fr2_val);
  set_fpr(r1, fr1_val);
  return length;
}

EVALUATE(CDFBRA) {
  DCHECK_OPCODE(CDFBRA);
  DECODE_RRE_INSTRUCTION(r1, r2);
  int32_t r2_val = get_low_register<int32_t>(r2);
  double r1_val = static_cast<double>(r2_val);
  set_fpr(r1, r1_val);
  return length;
}

EVALUATE(CXFBRA) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(FIDBRA) {
  DCHECK_OPCODE(FIDBRA);
  DECODE_RRF_E_INSTRUCTION(r1, r2, m3, m4);
  DCHECK_EQ(m4, 0);
  USE(m4);
  double a = get_fpr<double>(r2);
  double n = ComputeRounding<double>(a, m3);
  set_fpr(r1, n);
  return length;
}

EVALUATE(FIEBRA) {
  DCHECK_OPCODE(FIEBRA);
  DECODE_RRF_E_INSTRUCTION(r1, r2, m3, m4);
  DCHECK_EQ(m4, 0);
  USE(m4);
  float a = get_fpr<float>(r2);
  float n = ComputeRounding<float>(a, m3);
  set_fpr(r1, n);
  return length;
}

template <class T, class R>
static int ComputeSignedRoundingConditionCode(T a, T n) {
  constexpr T NINF = -std::numeric_limits<T>::infinity();
  constexpr T PINF = std::numeric_limits<T>::infinity();
  constexpr long double MN =
      static_cast<long double>(std::numeric_limits<R>::min());
  constexpr long double MP =
      static_cast<long double>(std::numeric_limits<R>::max());

  if (NINF <= a && a < MN && n < MN) {
    return 0x1;
  } else if (NINF < a && a < MN && n == MN) {
    return 0x4;
  } else if (MN <= a && a < 0.0) {
    return 0x4;
  } else if (a == 0.0) {
    return 0x8;
  } else if (0.0 < a && a <= MP) {
    return 0x2;
  } else if (MP < a && a <= PINF && n == MP) {
    return 0x2;
  } else if (MP < a && a <= PINF && n > MP) {
    return 0x1;
  } else if (std::isnan(a)) {
    return 0x1;
  }
  UNIMPLEMENTED();
  return 0;
}

EVALUATE(CFDBRA) {
  DCHECK_OPCODE(CFDBRA);
  DECODE_RRF_E_INSTRUCTION(r1, r2, m3, m4);
  DCHECK_EQ(m4, 0);
  USE(m4);
  double a = get_fpr<double>(r2);
  double n = ComputeRounding<double>(a, m3);
  int32_t r1_val = ComputeSignedRoundingResult<double, int32_t>(a, n);
  condition_reg_ = ComputeSignedRoundingConditionCode<double, int32_t>(a, n);

  set_low_register(r1, r1_val);
  return length;
}

EVALUATE(CFEBRA) {
  DCHECK_OPCODE(CFEBRA);
  DECODE_RRF_E_INSTRUCTION(r1, r2, m3, m4);
  DCHECK_EQ(m4, 0);
  USE(m4);
  float a = get_fpr<float>(r2);
  float n = ComputeRounding<float>(a, m3);
  int32_t r1_val = ComputeSignedRoundingResult<float, int32_t>(a, n);
  condition_reg_ = ComputeSignedRoundingConditionCode<float, int32_t>(a, n);

  set_low_register(r1, r1_val);
  return length;
}

EVALUATE(CGEBRA) {
  DCHECK_OPCODE(CGEBRA);
  DECODE_RRF_E_INSTRUCTION(r1, r2, m3, m4);
  DCHECK_EQ(m4, 0);
  USE(m4);
  float a = get_fpr<float>(r2);
  float n = ComputeRounding<float>(a, m3);
  int64_t r1_val = ComputeSignedRoundingResult<float, int64_t>(a, n);
  condition_reg_ = ComputeSignedRoundingConditionCode<float, int64_t>(a, n);

  set_register(r1, r1_val);
  return length;
}

EVALUATE(CGDBRA) {
  DCHECK_OPCODE(CGDBRA);
  DECODE_RRF_E_INSTRUCTION(r1, r2, m3, m4);
  DCHECK_EQ(m4, 0);
  USE(m4);
  double a = get_fpr<double>(r2);
  double n = ComputeRounding<double>(a, m3);
  int64_t r1_val = ComputeSignedRoundingResult<double, int64_t>(a, n);
  condition_reg_ = ComputeSignedRoundingConditionCode<double, int64_t>(a, n);

  set_register(r1, r1_val);
  return length;
}

EVALUATE(CGXBRA) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CFXBRA) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

template <class T, class R>
static int ComputeLogicalRoundingConditionCode(T a, T n) {
  constexpr T NINF = -std::numeric_limits<T>::infinity();
  constexpr T PINF = std::numeric_limits<T>::infinity();
  constexpr long double MP =
      static_cast<long double>(std::numeric_limits<R>::max());

  if (NINF <= a && a < 0.0) {
    return (n < 0.0) ? 0x1 : 0x4;
  } else if (a == 0.0) {
    return 0x8;
  } else if (0.0 < a && a <= MP) {
    return 0x2;
  } else if (MP < a && a <= PINF) {
    return n == MP ? 0x2 : 0x1;
  } else if (std::isnan(a)) {
    return 0x1;
  }
  UNIMPLEMENTED();
  return 0;
}

EVALUATE(CLFEBR) {
  DCHECK_OPCODE(CLFEBR);
  DECODE_RRF_E_INSTRUCTION(r1, r2, m3, m4);
  DCHECK_EQ(m4, 0);
  USE(m4);
  float a = get_fpr<float>(r2);
  float n = ComputeRounding<float>(a, m3);
  uint32_t r1_val = ComputeLogicalRoundingResult<float, uint32_t>(a, n);
  condition_reg_ = ComputeLogicalRoundingConditionCode<float, uint32_t>(a, n);

  set_low_register(r1, r1_val);
  return length;
}

EVALUATE(CLFDBR) {
  DCHECK_OPCODE(CLFDBR);
  DECODE_RRF_E_INSTRUCTION(r1, r2, m3, m4);
  DCHECK_EQ(m4, 0);
  USE(m4);
  double a = get_fpr<double>(r2);
  double n = ComputeRounding<double>(a, m3);
  uint32_t r1_val = ComputeLogicalRoundingResult<double, uint32_t>(a, n);
  condition_reg_ = ComputeLogicalRoundingConditionCode<double, uint32_t>(a, n);

  set_low_register(r1, r1_val);
  return length;
}

EVALUATE(CLGDBR) {
  DCHECK_OPCODE(CLGDBR);
  DECODE_RRF_E_INSTRUCTION(r1, r2, m3, m4);
  DCHECK_EQ(m4, 0);
  USE(m4);
  double a = get_fpr<double>(r2);
  double n = ComputeRounding<double>(a, m3);
  uint64_t r1_val = ComputeLogicalRoundingResult<double, uint64_t>(a, n);
  condition_reg_ = ComputeLogicalRoundingConditionCode<double, uint64_t>(a, n);

  set_register(r1, r1_val);
  return length;
}

EVALUATE(CLGEBR) {
  DCHECK_OPCODE(CLGEBR);
  DECODE_RRF_E_INSTRUCTION(r1, r2, m3, m4);
  DCHECK_EQ(m4, 0);
  USE(m4);
  float a = get_fpr<float>(r2);
  float n = ComputeRounding<float>(a, m3);
  uint64_t r1_val = ComputeLogicalRoundingResult<float, uint64_t>(a, n);
  condition_reg_ = ComputeLogicalRoundingConditionCode<float, uint64_t>(a, n);

  set_register(r1, r1_val);
  return length;
}

EVALUATE(CLFXBR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CELGBR) {
  DCHECK_OPCODE(CELGBR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  uint64_t r2_val = get_register(r2);
  float r1_val = static_cast<float>(r2_val);
  set_fpr(r1, r1_val);
  return length;
}

EVALUATE(CDLGBR) {
  DCHECK_OPCODE(CDLGBR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  uint64_t r2_val = get_register(r2);
  double r1_val = static_cast<double>(r2_val);
  set_fpr(r1, r1_val);
  return length;
}

EVALUATE(CXLGBR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CEGBRA) {
  DCHECK_OPCODE(CEGBRA);
  DECODE_RRE_INSTRUCTION(r1, r2);
  int64_t fr2_val = get_register(r2);
  float fr1_val = static_cast<float>(fr2_val);
  set_fpr(r1, fr1_val);
  return length;
}

EVALUATE(CDGBRA) {
  DCHECK_OPCODE(CDGBRA);
  DECODE_RRE_INSTRUCTION(r1, r2);
  int64_t r2_val = get_register(r2);
  double r1_val = static_cast<double>(r2_val);
  set_fpr(r1, r1_val);
  return length;
}

EVALUATE(CXGBRA) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CFER) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CFDR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CFXR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LDGR) {
  DCHECK_OPCODE(LDGR);
  // Load FPR from GPR (L <- 64)
  DECODE_RRE_INSTRUCTION(r1, r2);
  uint64_t int_val = get_register(r2);
  set_fpr(r1, int_val);
  return length;
}

EVALUATE(CGER) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CGDR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CGXR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LGDR) {
  DCHECK_OPCODE(LGDR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  // Load GPR from FPR (64 <- L)
  int64_t double_val = get_fpr<int64_t>(r2);
  set_register(r1, double_val);
  return length;
}

EVALUATE(MDTRA) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(DDTRA) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(ADTRA) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SDTRA) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LDETR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LEDTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LTDTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(FIDTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(MXTRA) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(DXTRA) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(AXTRA) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SXTRA) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LXDTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LDXTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LTXTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(FIXTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(KDTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CGDTRA) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CUDTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CDTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(EEDTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(ESDTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(KXTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CGXTRA) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CUXTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CSXTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CXTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(EEXTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(ESXTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CDGTRA) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CDUTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CDSTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CEDTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(QADTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(IEDTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(RRDTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CXGTRA) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CXUTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CXSTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CEXTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(QAXTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(IEXTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(RRXTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LPGR) {
  DCHECK_OPCODE(LPGR);
  // Load Positive (32)
  DECODE_RRE_INSTRUCTION(r1, r2);
  int64_t r2_val = get_register(r2);
  SetS390ConditionCode<int64_t>(r2_val, 0);
  if (r2_val == (static_cast<int64_t>(1) << 63)) {
    SetS390OverflowCode(true);
  } else {
    // If negative and not overflowing, then negate it.
    r2_val = (r2_val < 0) ? -r2_val : r2_val;
  }
  set_register(r1, r2_val);
  return length;
}

EVALUATE(LNGR) {
  DCHECK_OPCODE(LNGR);
  // Load Negative (64)
  DECODE_RRE_INSTRUCTION(r1, r2);
  int64_t r2_val = get_register(r2);
  r2_val = (r2_val >= 0) ? -r2_val : r2_val;  // If pos, then negate it.
  set_register(r1, r2_val);
  condition_reg_ = (r2_val == 0) ? CC_EQ : CC_LT;  // CC0 - result is zero
  // CC1 - result is negative
  return length;
}

EVALUATE(LTGR) {
  DCHECK_OPCODE(LTGR);
  // Load Register (64)
  DECODE_RRE_INSTRUCTION(r1, r2);
  int64_t r2_val = get_register(r2);
  SetS390ConditionCode<int64_t>(r2_val, 0);
  set_register(r1, get_register(r2));
  return length;
}

EVALUATE(LCGR) {
  DCHECK_OPCODE(LCGR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  int64_t r2_val = get_register(r2);
  int64_t result = 0;
  bool isOF = false;
  isOF = __builtin_ssubl_overflow(0L, r2_val, &result);
  set_register(r1, result);
  SetS390ConditionCode<int64_t>(result, 0);
  if (isOF) {
    SetS390OverflowCode(true);
  }
  return length;
}

EVALUATE(SGR) {
  DCHECK_OPCODE(SGR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  int64_t r1_val = get_register(r1);
  int64_t r2_val = get_register(r2);
  bool isOF = false;
  isOF = CheckOverflowForIntSub(r1_val, r2_val, int64_t);
  r1_val -= r2_val;
  SetS390ConditionCode<int64_t>(r1_val, 0);
  SetS390OverflowCode(isOF);
  set_register(r1, r1_val);
  return length;
}

EVALUATE(ALGR) {
  DCHECK_OPCODE(ALGR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  // 64-bit Non-clobbering unsigned arithmetics
  uint64_t r1_val = get_register(r1);
  uint64_t r2_val = get_register(r2);
  bool isOF = CheckOverflowForUIntAdd(r1_val, r2_val);
  SetS390ConditionCode<uint64_t>(r1_val + r2_val, 0);
  SetS390OverflowCode(isOF);
  set_register(r1, r1_val + r2_val);
  return length;
}

EVALUATE(SLGR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(MSGR) {
  DCHECK_OPCODE(MSGR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  int64_t r1_val = get_register(r1);
  int64_t r2_val = get_register(r2);
  set_register(r1, r1_val * r2_val);
  return length;
}

EVALUATE(MSGRKC) {
  DCHECK_OPCODE(MSGRKC);
  DECODE_RRF_A_INSTRUCTION(r1, r2, r3);
  int64_t r2_val = get_register(r2);
  int64_t r3_val = get_register(r3);
  volatile int64_t result64 = r2_val * r3_val;
  bool isOF = ((r2_val == -1 && result64 == (static_cast<int64_t>(1L) << 63)) ||
               (r2_val != 0 && result64 / r2_val != r3_val));
  SetS390ConditionCode<int64_t>(result64, 0);
  SetS390OverflowCode(isOF);
  set_register(r1, result64);
  return length;
}

EVALUATE(DSGR) {
  DCHECK_OPCODE(DSGR);
  DECODE_RRE_INSTRUCTION(r1, r2);

  DCHECK_EQ(r1 % 2, 0);

  int64_t dividend = get_register(r1 + 1);
  int64_t divisor = get_register(r2);
  set_register(r1, dividend % divisor);
  set_register(r1 + 1, dividend / divisor);
  return length;
}

EVALUATE(LRVGR) {
  DCHECK_OPCODE(LRVGR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  int64_t r2_val = get_register(r2);
  int64_t r1_val = ByteReverse<int64_t>(r2_val);

  set_register(r1, r1_val);
  return length;
}

EVALUATE(LPGFR) {
  DCHECK_OPCODE(LPGFR);
  // Load Positive (32)
  DECODE_RRE_INSTRUCTION(r1, r2);
  int32_t r2_val = get_low_register<int32_t>(r2);
  // If negative, then negate it.
  int64_t r1_val = static_cast<int64_t>((r2_val < 0) ? -r2_val : r2_val);
  set_register(r1, r1_val);
  SetS390ConditionCode<int64_t>(r1_val, 0);
  return length;
}

EVALUATE(LNGFR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LTGFR) {
  DCHECK_OPCODE(LTGFR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  // Load and Test Register (64 <- 32)  (Sign Extends 32-bit val)
  // Load Register (64 <- 32)  (Sign Extends 32-bit val)
  int32_t r2_val = get_low_register<int32_t>(r2);
  int64_t result = static_cast<int64_t>(r2_val);
  set_register(r1, result);
  SetS390ConditionCode<int64_t>(result, 0);
  return length;
}

EVALUATE(LCGFR) {
  DCHECK_OPCODE(LCGFR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  // Load and Test Register (64 <- 32)  (Sign Extends 32-bit val)
  // Load Register (64 <- 32)  (Sign Extends 32-bit val)
  int32_t r2_val = get_low_register<int32_t>(r2);
  int64_t result = static_cast<int64_t>(r2_val);
  set_register(r1, result);
  return length;
}

EVALUATE(LLGFR) {
  DCHECK_OPCODE(LLGFR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  int32_t r2_val = get_low_register<int32_t>(r2);
  uint64_t r2_finalval = (static_cast<uint64_t>(r2_val) & 0x00000000FFFFFFFF);
  set_register(r1, r2_finalval);
  return length;
}

EVALUATE(LLGTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(AGFR) {
  DCHECK_OPCODE(AGFR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  // Add Register (64 <- 32)  (Sign Extends 32-bit val)
  int64_t r1_val = get_register(r1);
  int64_t r2_val = static_cast<int64_t>(get_low_register<int32_t>(r2));
  bool isOF = CheckOverflowForIntAdd(r1_val, r2_val, int64_t);
  r1_val += r2_val;
  SetS390ConditionCode<int64_t>(r1_val, 0);
  SetS390OverflowCode(isOF);
  set_register(r1, r1_val);
  return length;
}

EVALUATE(SGFR) {
  DCHECK_OPCODE(SGFR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  // Sub Reg (64 <- 32)
  int64_t r1_val = get_register(r1);
  int64_t r2_val = static_cast<int64_t>(get_low_register<int32_t>(r2));
  bool isOF = false;
  isOF = CheckOverflowForIntSub(r1_val, r2_val, int64_t);
  r1_val -= r2_val;
  SetS390ConditionCode<int64_t>(r1_val, 0);
  SetS390OverflowCode(isOF);
  set_register(r1, r1_val);
  return length;
}

EVALUATE(ALGFR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SLGFR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(MSGFR) {
  DCHECK_OPCODE(MSGFR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  int64_t r1_val = get_register(r1);
  int64_t r2_val = static_cast<int64_t>(get_low_register<int32_t>(r2));
  int64_t product = r1_val * r2_val;
  set_register(r1, product);
  return length;
}

EVALUATE(DSGFR) {
  DCHECK_OPCODE(DSGFR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  DCHECK_EQ(r1 % 2, 0);
  int64_t r1_val = get_register(r1 + 1);
  int64_t r2_val = static_cast<int64_t>(get_low_register<int32_t>(r2));
  int64_t quotient = r1_val / r2_val;
  int64_t remainder = r1_val % r2_val;
  set_register(r1, remainder);
  set_register(r1 + 1, quotient);
  return length;
}

EVALUATE(KMAC) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LRVR) {
  DCHECK_OPCODE(LRVR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  int32_t r2_val = get_low_register<int32_t>(r2);
  int32_t r1_val = ByteReverse<int32_t>(r2_val);

  set_low_register(r1, r1_val);
  return length;
}

EVALUATE(CGR) {
  DCHECK_OPCODE(CGR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  // Compare (64)
  int64_t r1_val = get_register(r1);
  int64_t r2_val = get_register(r2);
  SetS390ConditionCode<int64_t>(r1_val, r2_val);
  return length;
}

EVALUATE(CLGR) {
  DCHECK_OPCODE(CLGR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  // Compare Logical (64)
  uint64_t r1_val = static_cast<uint64_t>(get_register(r1));
  uint64_t r2_val = static_cast<uint64_t>(get_register(r2));
  SetS390ConditionCode<uint64_t>(r1_val, r2_val);
  return length;
}

EVALUATE(KMF) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(KMO) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(PCC) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(KMCTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(KM) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(KMC) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CGFR) {
  DCHECK_OPCODE(CGFR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  // Compare (64)
  int64_t r1_val = get_register(r1);
  int64_t r2_val = static_cast<int64_t>(get_low_register<int32_t>(r2));
  SetS390ConditionCode<int64_t>(r1_val, r2_val);
  return length;
}

EVALUATE(KIMD) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(KLMD) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CFDTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CLGDTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CLFDTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(BCTGR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CFXTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CLFXTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CDFTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CDLGTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CDLFTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CXFTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CXLGTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CXLFTR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CGRT) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(NGR) {
  DCHECK_OPCODE(NGR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  int64_t r1_val = get_register(r1);
  int64_t r2_val = get_register(r2);
  r1_val &= r2_val;
  SetS390BitWiseConditionCode<uint64_t>(r1_val);
  set_register(r1, r1_val);
  return length;
}

EVALUATE(OGR) {
  DCHECK_OPCODE(OGR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  int64_t r1_val = get_register(r1);
  int64_t r2_val = get_register(r2);
  r1_val |= r2_val;
  SetS390BitWiseConditionCode<uint64_t>(r1_val);
  set_register(r1, r1_val);
  return length;
}

EVALUATE(XGR) {
  DCHECK_OPCODE(XGR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  int64_t r1_val = get_register(r1);
  int64_t r2_val = get_register(r2);
  r1_val ^= r2_val;
  SetS390BitWiseConditionCode<uint64_t>(r1_val);
  set_register(r1, r1_val);
  return length;
}

EVALUATE(FLOGR) {
  DCHECK_OPCODE(FLOGR);
  DECODE_RRE_INSTRUCTION(r1, r2);

  DCHECK_EQ(r1 % 2, 0);

  int64_t r2_val = get_register(r2);

  int i = 0;
  for (; i < 64; i++) {
    if (r2_val < 0) break;
    r2_val <<= 1;
  }

  r2_val = get_register(r2);

  int64_t mask = ~(1 << (63 - i));
  set_register(r1, i);
  set_register(r1 + 1, r2_val & mask);
  return length;
}

EVALUATE(LLGCR) {
  DCHECK_OPCODE(LLGCR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  uint64_t r2_val = get_low_register<uint64_t>(r2);
  r2_val <<= 56;
  r2_val >>= 56;
  set_register(r1, r2_val);
  return length;
}

EVALUATE(LLGHR) {
  DCHECK_OPCODE(LLGHR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  uint64_t r2_val = get_low_register<uint64_t>(r2);
  r2_val <<= 48;
  r2_val >>= 48;
  set_register(r1, r2_val);
  return length;
}

EVALUATE(MG) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(MGRK) {
  DCHECK_OPCODE(MGRK);
  DECODE_RRF_A_INSTRUCTION(r1, r2, r3);
  // 64-bit Non-clobbering arithmetics / bitwise ops.
  int64_t r2_val = get_register(r2);
  int64_t r3_val = get_register(r3);
  set_register(r1, base::bits::SignedMulHigh64(r2_val, r3_val));
  set_register(r1 + 1, r2_val * r3_val);
  return length;
}

EVALUATE(MLGR) {
  DCHECK_OPCODE(MLGR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  // 64-bit Non-clobbering unsigned arithmetics
  CHECK_EQ(r1 % 2, 0);
  uint64_t r1_plus_1_val = get_register(r1 + 1);
  uint64_t r2_val = get_register(r2);

  set_register(r1, base::bits::UnsignedMulHigh64(r2_val, r1_plus_1_val));
  set_register(r1 + 1, r2_val * r1_plus_1_val);
  return length;
}

EVALUATE(MLG) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(DLGR) {
  DCHECK_OPCODE(DLGR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  uint64_t r1_val = get_register(r1);
  uint64_t r2_val = get_register(r2);
  DCHECK_EQ(r1 % 2, 0);
  unsigned __int128 dividend = static_cast<unsigned __int128>(r1_val) << 64;
  dividend += get_register(r1 + 1);
  uint64_t remainder = dividend % r2_val;
  uint64_t quotient = dividend / r2_val;
  set_register(r1, remainder);
  set_register(r1 + 1, quotient);
  return length;
}

EVALUATE(ALCGR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SLBGR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(EPSW) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(TRTT) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(TRTO) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(TROT) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(TROO) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(LLCR) {
  DCHECK_OPCODE(LLCR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  uint32_t r2_val = get_low_register<uint32_t>(r2);
  r2_val <<= 24;
  r2_val >>= 24;
  set_low_register(r1, r2_val);
  return length;
}

EVALUATE(LLHR) {
  DCHECK_OPCODE(LLHR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  uint32_t r2_val = get_low_register<uint32_t>(r2);
  r2_val <<= 16;
  r2_val >>= 16;
  set_low_register(r1, r2_val);
  return length;
}

EVALUATE(MLR) {
  DCHECK_OPCODE(MLR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  DCHECK_EQ(r1 % 2, 0);

  uint32_t r1_val = get_low_register<uint32_t>(r1 + 1);
  uint32_t r2_val = get_low_register<uint32_t>(r2);
  uint64_t product =
      static_cast<uint64_t>(r1_val) * static_cast<uint64_t>(r2_val);
  int32_t high_bits = product >> 32;
  int32_t low_bits = product & 0x00000000FFFFFFFF;
  set_low_register(r1, high_bits);
  set_low_register(r1 + 1, low_bits);
  return length;
}

EVALUATE(DLR) {
  DCHECK_OPCODE(DLR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  uint32_t r1_val = get_low_register<uint32_t>(r1);
  uint32_t r2_val = get_low_register<uint32_t>(r2);
  DCHECK_EQ(r1 % 2, 0);
  uint64_t dividend = static_cast<uint64_t>(r1_val) << 32;
  dividend += get_low_register<uint32_t>(r1 + 1);
  uint32_t remainder = dividend % r2_val;
  uint32_t quotient = dividend / r2_val;
  r1_val = remainder;
  set_low_register(r1, remainder);
  set_low_register(r1 + 1, quotient);
  return length;
}

EVALUATE(ALCR) {
  DCHECK_OPCODE(ALCR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  uint32_t r1_val = get_low_register<uint32_t>(r1);
  uint32_t r2_val = get_low_register<uint32_t>(r2);
  uint32_t alu_out = 0;
  bool isOF = false;

  alu_out = r1_val + r2_val;
  bool isOF_original = CheckOverflowForUIntAdd(r1_val, r2_val);
  if (TestConditionCode((Condition)2) || TestConditionCode((Condition)3)) {
    alu_out = alu_out + 1;
    isOF = isOF_original || CheckOverflowForUIntAdd(alu_out, 1);
  } else {
    isOF = isOF_original;
  }
  set_low_register(r1, alu_out);
  SetS390ConditionCodeCarry<uint32_t>(alu_out, isOF);
  return length;
}

EVALUATE(SLBR) {
  DCHECK_OPCODE(SLBR);
  DECODE_RRE_INSTRUCTION(r1, r2);
  uint32_t r1_val = get_low_register<uint32_t>(r1);
  uint32_t r2_val = get_low_register<uint32_t>(r2);
  uint32_t alu_out = 0;
  bool isOF = false;

  alu_out = r1_val - r2_val;
  bool isOF_original = CheckOverflowForUIntSub(r1_val, r2_val);
  if (TestConditionCode((Condition)2) || TestConditionCode((Condition)3)) {
    alu_out = alu_out - 1;
    isOF = isOF_original || CheckOverflowForUIntSub(alu_out, 1);
  } else {
    isOF = isOF_original;
  }
  set_low_register(r1, alu_out);
  SetS390ConditionCodeCarry<uint32_t>(alu_out, isOF);
  return length;
}

EVALUATE(CU14) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CU24) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CU41) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CU42) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(TRTRE) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SRSTU) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(TRTE) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(AHHHR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SHHHR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(ALHHHR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SLHHHR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CHHR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(AHHLR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SHHLR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(ALHHLR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(SLHHLR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(CHLR) {
  UNIMPLEMENTED();
  USE(instr);
  return 0;
}

EVALUATE(POPCNT_Z) {
  DCHECK_OPCODE(POPCNT_Z);
  DECODE_RRE_INSTRUCTION(r1, r2);
  int64_t r2_val = get_register(r2);
  int64_t r1_val = 0;

  uint8_t* r2_val_ptr = reinterpret_cast<uint8_t*>(&r2_val);
  uint8_t* r1_val_ptr = reinterpret_cast<uint8_t*>(&r1_val);
  for (int i = 0; i < 8; i++) {
    uint32_t x = static_cast<uint32_t>(r2_val_ptr[i]);
#if defined(__GNUC__)
    r1_val_ptr[i] = __builtin_popcount(x);
#else
#error unsupport __builtin_popcount
#endif
  }
  set_register(r1, static_cast<uint64_t>(r1_val));
  return length;
}

EVALUATE(LOCGR) {
  DCHECK_OPCODE(LOCGR);
  DECODE_RRF_C_INSTRUCTION(r1, r2, m3);
  if (TestConditionCode(m3)) {
    set_register(r1, get_register(r2));
  }
  return length;
}

EVALUATE(NGRK) {
  DCHECK_OPCODE(NGRK);
  DECODE_RRF_A_INSTRUCTION(r1, r2, r3);
  // 64-bit Non-clobbering arithmetics / bitwise ops.
  int64_t r2_val = get_register(r2);
  int64_t r3_val = get_register(r3);
  uint64_t bitwise_result = 0;
  bitwise_result = r2_val & r3_val;
  SetS390BitWiseConditionCode<uint64_t>(bitwise_result);
  set_register(r1, bitwise_result);
  return length;
}

EVALUATE(OGRK) {
  DCHECK_OPCODE(OGRK);
  DECODE_RRF_A_INSTRUCTION(r1, r2, r3);
  // 64-bit Non-clobbering arithmetics / bitwise ops.
  int64_t r2_val = get_register(r2);
  int64_t r3_val = get_register(r3);
  uint64_t bitwise_result = 0;
  bitwise_result = r2_val | r3_val;
  SetS390BitWiseConditionCode<uint64_t>(bitwise_result);
  set_register(r1, bitwise_result);
  return length;
}

EVALUATE(XGRK) {
  DCHECK_OPCODE(XGRK);
  DECODE_RRF_A_INSTRUCTION(r1, r2, r3);
  // 64-bit Non-clobbering arithmetics / bitwise ops.
  int64_t r2_val = get_register(r2);
  int64_t r3_val = get_register(r3);
  uint64_t bitwise_result = 0;
  bitwise_result = r2_val ^ r3_val;
  SetS390BitWiseConditionCode<uint64_t>(bitwise_result);
  set_register(r1, bitwise_result);
  return length;
}

EVALUATE(AGRK) {
  DCHECK_OPCODE(AGRK);
  DE
```