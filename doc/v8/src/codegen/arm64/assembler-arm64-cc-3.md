Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/codegen/arm64/assembler-arm64.cc`.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Purpose:** The filename `assembler-arm64.cc` strongly suggests this code is responsible for generating ARM64 assembly instructions. The `Assembler` class name reinforces this.

2. **Scan for Key Methods:**  Look for method names and patterns. A significant number of methods start with `fmov`, `fcmp`, `fcvt`, `NEON`, etc. These prefixes are indicative of the types of operations being performed.

3. **Group Functionality:** Based on the method prefixes and names, categorize the functionalities:
    * **Barriers:** `dsb`, `isb`, `csdb` clearly relate to memory barriers.
    * **Floating-Point Operations:**  Methods starting with `f` (like `fmov`, `fmadd`, `fcmp`, `fcvt`, `frecp`) deal with floating-point numbers. Notice the variations for different sizes (s, d).
    * **NEON/SIMD Operations:** Methods starting with `NEON` (like `NEONFPConvertToInt`, `NEON3Same`, `NEONByElement`) are related to ARM's Advanced SIMD (NEON) instructions for parallel processing.
    * **Conversions:** The `fcvt` family of functions handle conversions between different floating-point types and between floating-point and integer types.
    * **Comparisons:** The `fcmp` and `fccmp` functions perform floating-point comparisons.
    * **Selections:** `fcsel` selects a value based on a condition.
    * **Arithmetic Operations:**  Methods like `fmadd`, `fmsub`, `fnmul` perform arithmetic operations on floating-point numbers. The NEON equivalents (`add`, `sub`, `mul`, etc.) handle vector arithmetic.
    * **Bitwise Operations:**  NEON instructions like `orr`, `bic`, `and_`, `eor` perform bitwise logical operations.
    * **Shifts and Rotations:**  Methods like `shll` and the shift parameters in `movi` and `mvni` suggest bit shifting operations.
    * **Absolute Value, Negation:**  `fabs`, `fneg`, `sqabs`, `sqneg` handle these operations.
    * **Square Root, Reciprocal:** `fsqrt`, `frsqrte`, `frecpe` are for mathematical functions.

4. **Consider the ".tq" Check:** The prompt mentions checking for a `.tq` extension, indicating Torque code generation. While not directly evident in the provided snippet, acknowledge this possibility and explain what Torque is.

5. **Address the JavaScript Relationship:** Since V8 is a JavaScript engine, consider how these low-level assembly operations relate to JavaScript. Think about common JavaScript operations that might map to these instructions (e.g., arithmetic, comparisons, array manipulation that could use SIMD). Provide concrete JavaScript examples.

6. **Code Logic and Assumptions:** Look for patterns in how the methods are used. Notice the `DCHECK` calls, which are assertions to ensure certain conditions are met. Consider simple examples of how some of these instructions might be used. For instance, moving a floating-point immediate value. Provide a simple input and output scenario.

7. **Common Programming Errors:** Think about potential pitfalls when working with low-level operations or floating-point numbers. Examples include incorrect data types, precision issues, and misunderstanding the behavior of barrier instructions.

8. **Structure the Summary:** Organize the findings into logical sections based on the identified functionalities. Use clear headings and concise descriptions.

9. **Review and Refine:**  Read through the generated summary to ensure clarity, accuracy, and completeness based on the provided code. Ensure all parts of the prompt are addressed. For example, the "part 4 of 6" instruction suggests focusing on summarizing the functionality *within this specific snippet*, not the entire file.

By following these steps, you can effectively analyze the code snippet and generate a comprehensive summary of its functionality, as demonstrated in the provided good answer.
Based on the provided C++ code snippet from `v8/src/codegen/arm64/assembler-arm64.cc`, here's a breakdown of its functionalities:

**Core Functionality: ARM64 Assembly Instruction Generation**

This code snippet is part of the V8 JavaScript engine's ARM64 assembler. Its primary function is to provide a high-level C++ interface for emitting raw ARM64 machine code instructions. It allows V8's code generator to produce efficient native code for ARM64 architectures.

**Specific Function Groups:**

1. **Memory Barriers:**
   - `dsb(BarrierDomain domain, BarrierType type)`: Emits a Data Synchronization Barrier (DSB) instruction, ensuring memory operations are completed in a specific order.
   - `isb()`: Emits an Instruction Synchronization Barrier (ISB) instruction, ensuring that instructions fetched after the barrier are affected by the context established by instructions executed before the barrier.
   - `csdb()`: Emits a Context Synchronization Barrier (CSDB) hint, a weaker form of memory barrier.

2. **Floating-Point Move Instructions (`fmov`):**
   - It provides various overloads of `fmov` to move floating-point values between:
     - Floating-point registers (scalar and vector).
     - Immediate floating-point values and floating-point registers.
     - General-purpose registers and floating-point registers.
     - Specific elements within vector registers and general-purpose registers.

3. **Floating-Point Arithmetic Instructions:**
   - `fmadd`, `fmsub`, `fnmadd`, `fnmsub`:  Fused Multiply-Add and Multiply-Subtract operations (including negated versions).
   - `fnmul`: Floating-point negate multiply.

4. **Floating-Point Comparison Instructions (`fcmp`, `fccmp`):**
   - `fcmp`: Compares two floating-point registers or a floating-point register with zero.
   - `fccmp`: Compares two floating-point registers and conditionally sets the status flags based on a given condition.

5. **Floating-Point Conditional Select (`fcsel`):**
   - Selects one of two floating-point registers based on a condition.

6. **Floating-Point Conversion Instructions (`fcvt`, `fcvtl`, `fcvtn`, `fcvtxn`, `fjcvtzs`, `scvtf`, `ucvtf`, `fcvtzs`, `fcvtzu`):**
   - Converts between different floating-point precisions (half, single, double).
   - Converts between floating-point and integer types (signed and unsigned).
   - Includes rounding modes (e.g., nearest, toward zero).
   - Some conversions operate on scalar registers, others on vector registers.

7. **NEON (Advanced SIMD) Instructions:**
   - This section provides a large number of functions for generating NEON instructions, which enable Single Instruction, Multiple Data (SIMD) operations for parallel processing of vectors.
   - **Conversions:** `NEONFPConvertToInt` (floating-point to integer), `fcvtl`, `fcvtn`, `fcvtxn` (lane widening/narrowing).
   - **Arithmetic:** `NEON3Same` (generic 3-operand), `NEONFP3Same` (floating-point 3-operand), `add`, `sub`, `mul`, `div`, `faddp` (pairwise add).
   - **Comparison:** `cmeq`, `cmge`, `cmgt`, `cmle`, `cmlt` (compare with zero), `cmhi`, `cmhs`, `cmtst`.
   - **Logical:** `and_`, `orr`, `orn`, `eor`, `bic`, `bit`, `bif`, `bsl`, `pmul`.
   - **Shift/Rotate:** `sshl`, `ushl`, `srshl`, `urshl`, `shll`.
   - **Absolute Value/Negation:** `abs`, `neg`, `sqabs`, `sqneg`.
   - **Saturating Arithmetic:** `uqadd`, `sqadd`, `uqsub`, `sqsub`, `sqshl`, `uqshl`, `sqrshl`, `uqrshl`, `suqadd`, `usqadd`.
   - **Maximum/Minimum:** `smax`, `smin`, `umax`, `umin`, `fmax`, `fmin`, `fmaxnm`, `fminnm`.
   - **Accumulation:** `saba`, `sabd`, `uaba`, `uabd`, `mla`, `mls`, `fmla`, `fmls`.
   - **Reciprocal/Square Root Estimates:** `frsqrte`, `frecpe`, `frecps`, `frsqrts`.
   - **By Element Operations:**  Variants of arithmetic and logical operations that operate between a vector and a single element of another vector (`NEONByElement`, `NEONFPByElement`, `NEONByElementL`).
   - **Modified Immediate Values:** `orr`, `movi`, `bic`, `mvni` (loading immediate values into vector registers).
   - **Lane Extraction/Insertion (Implicit):** Some instructions like `fmov` with index implicitly handle lane operations.
   - **Reduction Operations:** `addp`, `faddp`, `fmaxp`, `fminp`, `fmaxnmp`, `fminnmp`.

**Is it a Torque Source?**

The prompt states: "如果v8/src/codegen/arm64/assembler-arm64.cc以.tq结尾，那它是个v8 torque源代码". Since the provided file ends with `.cc`, it is **not** a Torque source file. Torque files use the `.tq` extension and are used for a higher-level description of code generation logic. This `.cc` file contains the actual C++ implementation of the assembler.

**Relationship to JavaScript and Examples:**

This code directly underpins the execution of JavaScript code on ARM64 architectures. When V8 compiles JavaScript, it uses this assembler to generate the low-level machine instructions that the processor executes.

**JavaScript Examples:**

1. **Basic Arithmetic:**
   ```javascript
   function add(a, b) {
     return a + b;
   }
   ```
   Internally, V8 might use instructions like `fadd` (for floating-point numbers) or `add` (for integers via NEON or general-purpose registers) from this assembler to implement the `+` operation.

2. **Array Operations (Potential use of NEON):**
   ```javascript
   const arr1 = [1.0, 2.0, 3.0, 4.0];
   const arr2 = [5.0, 6.0, 7.0, 8.0];
   const result = arr1.map((x, i) => x * arr2[i]);
   ```
   V8 could potentially use NEON instructions like `fmul` (vector floating-point multiplication) to perform the element-wise multiplication efficiently.

3. **Floating-Point Math Functions:**
   ```javascript
   Math.sqrt(2.0);
   ```
   This might translate to the `fsqrt` instruction provided by the assembler.

**Code Logic Inference and Examples:**

Many of the functions in this snippet directly map to specific ARM64 instructions. The logic is primarily about correctly encoding the operands and instruction opcodes.

**Example:**

```c++
void Assembler::fmov(const VRegister& vd, double imm) {
  if (vd.IsScalar()) {
    DCHECK(vd.Is1D());
    Emit(FMOV_d_imm | Rd(vd) | ImmFP(imm));
  } else {
    // ... (vector case)
  }
}
```

**Assumptions:**

* **Input:** `vd` is a `VRegister` object representing a floating-point register, `imm` is a `double` value.
* **Scenario:**  Moving an immediate double-precision floating-point value into a scalar register.
* **Output:** Emits the ARM64 instruction `FMOV` with the appropriate register encoding (`Rd(vd)`) and immediate value encoding (`ImmFP(imm)`).

**Example Input/Output (Conceptual ARM64 assembly):**

If `vd` represents register `d0` and `imm` is `3.14`, the generated instruction would conceptually be similar to:

```assembly
FMOV D0, #3.14
```

**Common Programming Errors (Within V8 Development):**

When working with assemblers, common errors include:

1. **Incorrect Register Encoding:**  Using the wrong bits to specify the destination or source registers. This can lead to the instruction operating on the wrong data or crashing.
   ```c++
   // Incorrect: Assuming Rn and Rd are the same offset
   Emit(ADD | Rd(destination_reg) | Rd(source_reg));
   ```

2. **Incorrect Immediate Encoding:**  Encoding immediate values in the wrong format or exceeding the allowed range.
   ```c++
   // Incorrect: Immediate value too large for the instruction
   Emit(MOV  | Rd(reg) | Imm16(0xFFFFF));
   ```

3. **Mismatched Data Types/Sizes:** Trying to operate on registers or memory locations with incompatible data types or sizes.
   ```c++
   // Incorrect: Moving a 64-bit value to a 32-bit register
   Emit(MOVw | Rd(w_register) | Rn(x_register));
   ```

4. **Incorrect Instruction Selection:** Choosing the wrong instruction for the intended operation.
   ```c++
   // Incorrect: Using a signed shift for an unsigned value
   Emit(ASR | ...); // Should be LSR
   ```

5. **Forgetting Memory Barriers:**  In multithreaded scenarios, failing to insert appropriate memory barriers can lead to data races and unpredictable behavior.

**Summary of Functionality (Part 4):**

This specific part of the `assembler-arm64.cc` file focuses heavily on providing the building blocks for generating **floating-point and NEON (SIMD) instructions** for the ARM64 architecture. It includes functions for moving data, performing arithmetic, comparisons, conversions, and logical operations on floating-point numbers and vectors. It also includes functions for emitting memory barrier instructions to ensure proper memory ordering. The code is crucial for V8's ability to efficiently execute JavaScript code on ARM64 processors by generating optimized native machine code.

Prompt: 
```
这是目录为v8/src/codegen/arm64/assembler-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/arm64/assembler-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共6部分，请归纳一下它的功能

"""
type));
}

void Assembler::dsb(BarrierDomain domain, BarrierType type) {
  Emit(DSB | ImmBarrierDomain(domain) | ImmBarrierType(type));
}

void Assembler::isb() {
  Emit(ISB | ImmBarrierDomain(FullSystem) | ImmBarrierType(BarrierAll));
}

void Assembler::csdb() { hint(CSDB); }

void Assembler::fmov(const VRegister& vd, double imm) {
  if (vd.IsScalar()) {
    DCHECK(vd.Is1D());
    Emit(FMOV_d_imm | Rd(vd) | ImmFP(imm));
  } else {
    DCHECK(vd.Is2D());
    Instr op = NEONModifiedImmediate_MOVI | NEONModifiedImmediateOpBit;
    Emit(NEON_Q | op | ImmNEONFP(imm) | NEONCmode(0xF) | Rd(vd));
  }
}

void Assembler::fmov(const VRegister& vd, float imm) {
  if (vd.IsScalar()) {
    DCHECK(vd.Is1S());
    Emit(FMOV_s_imm | Rd(vd) | ImmFP(imm));
  } else {
    DCHECK(vd.Is2S() || vd.Is4S());
    Instr op = NEONModifiedImmediate_MOVI;
    Instr q = vd.Is4S() ? NEON_Q : 0;
    Emit(q | op | ImmNEONFP(imm) | NEONCmode(0xF) | Rd(vd));
  }
}

void Assembler::fmov(const Register& rd, const VRegister& fn) {
  DCHECK_EQ(rd.SizeInBits(), fn.SizeInBits());
  FPIntegerConvertOp op = rd.Is32Bits() ? FMOV_ws : FMOV_xd;
  Emit(op | Rd(rd) | Rn(fn));
}

void Assembler::fmov(const VRegister& vd, const Register& rn) {
  DCHECK_EQ(vd.SizeInBits(), rn.SizeInBits());
  FPIntegerConvertOp op = vd.Is32Bits() ? FMOV_sw : FMOV_dx;
  Emit(op | Rd(vd) | Rn(rn));
}

void Assembler::fmov(const VRegister& vd, const VRegister& vn) {
  DCHECK_EQ(vd.SizeInBits(), vn.SizeInBits());
  Emit(FPType(vd) | FMOV | Rd(vd) | Rn(vn));
}

void Assembler::fmov(const VRegister& vd, int index, const Register& rn) {
  DCHECK((index == 1) && vd.Is1D() && rn.IsX());
  USE(index);
  Emit(FMOV_d1_x | Rd(vd) | Rn(rn));
}

void Assembler::fmov(const Register& rd, const VRegister& vn, int index) {
  DCHECK((index == 1) && vn.Is1D() && rd.IsX());
  USE(index);
  Emit(FMOV_x_d1 | Rd(rd) | Rn(vn));
}

void Assembler::fmadd(const VRegister& fd, const VRegister& fn,
                      const VRegister& fm, const VRegister& fa) {
  FPDataProcessing3Source(fd, fn, fm, fa, fd.Is32Bits() ? FMADD_s : FMADD_d);
}

void Assembler::fmsub(const VRegister& fd, const VRegister& fn,
                      const VRegister& fm, const VRegister& fa) {
  FPDataProcessing3Source(fd, fn, fm, fa, fd.Is32Bits() ? FMSUB_s : FMSUB_d);
}

void Assembler::fnmadd(const VRegister& fd, const VRegister& fn,
                       const VRegister& fm, const VRegister& fa) {
  FPDataProcessing3Source(fd, fn, fm, fa, fd.Is32Bits() ? FNMADD_s : FNMADD_d);
}

void Assembler::fnmsub(const VRegister& fd, const VRegister& fn,
                       const VRegister& fm, const VRegister& fa) {
  FPDataProcessing3Source(fd, fn, fm, fa, fd.Is32Bits() ? FNMSUB_s : FNMSUB_d);
}

void Assembler::fnmul(const VRegister& vd, const VRegister& vn,
                      const VRegister& vm) {
  DCHECK(AreSameSizeAndType(vd, vn, vm));
  Instr op = vd.Is1S() ? FNMUL_s : FNMUL_d;
  Emit(FPType(vd) | op | Rm(vm) | Rn(vn) | Rd(vd));
}

void Assembler::fcmp(const VRegister& fn, const VRegister& fm) {
  DCHECK_EQ(fn.SizeInBits(), fm.SizeInBits());
  Emit(FPType(fn) | FCMP | Rm(fm) | Rn(fn));
}

void Assembler::fcmp(const VRegister& fn, double value) {
  USE(value);
  // Although the fcmp instruction can strictly only take an immediate value of
  // +0.0, we don't need to check for -0.0 because the sign of 0.0 doesn't
  // affect the result of the comparison.
  DCHECK_EQ(value, 0.0);
  Emit(FPType(fn) | FCMP_zero | Rn(fn));
}

void Assembler::fccmp(const VRegister& fn, const VRegister& fm,
                      StatusFlags nzcv, Condition cond) {
  DCHECK_EQ(fn.SizeInBits(), fm.SizeInBits());
  Emit(FPType(fn) | FCCMP | Rm(fm) | Cond(cond) | Rn(fn) | Nzcv(nzcv));
}

void Assembler::fcsel(const VRegister& fd, const VRegister& fn,
                      const VRegister& fm, Condition cond) {
  DCHECK_EQ(fd.SizeInBits(), fn.SizeInBits());
  DCHECK_EQ(fd.SizeInBits(), fm.SizeInBits());
  Emit(FPType(fd) | FCSEL | Rm(fm) | Cond(cond) | Rn(fn) | Rd(fd));
}

void Assembler::NEONFPConvertToInt(const Register& rd, const VRegister& vn,
                                   Instr op) {
  Emit(SF(rd) | FPType(vn) | op | Rn(vn) | Rd(rd));
}

void Assembler::NEONFPConvertToInt(const VRegister& vd, const VRegister& vn,
                                   Instr op) {
  if (vn.IsScalar()) {
    DCHECK((vd.Is1S() && vn.Is1S()) || (vd.Is1D() && vn.Is1D()));
    op |= NEON_Q | NEONScalar;
  }
  Emit(FPFormat(vn) | op | Rn(vn) | Rd(vd));
}

void Assembler::fcvt(const VRegister& vd, const VRegister& vn) {
  FPDataProcessing1SourceOp op;
  if (vd.Is1D()) {
    DCHECK(vn.Is1S() || vn.Is1H());
    op = vn.Is1S() ? FCVT_ds : FCVT_dh;
  } else if (vd.Is1S()) {
    DCHECK(vn.Is1D() || vn.Is1H());
    op = vn.Is1D() ? FCVT_sd : FCVT_sh;
  } else {
    DCHECK(vd.Is1H());
    DCHECK(vn.Is1D() || vn.Is1S());
    op = vn.Is1D() ? FCVT_hd : FCVT_hs;
  }
  FPDataProcessing1Source(vd, vn, op);
}

void Assembler::fcvtl(const VRegister& vd, const VRegister& vn) {
  DCHECK((vd.Is4S() && vn.Is4H()) || (vd.Is2D() && vn.Is2S()));
  Instr format = vd.Is2D() ? (1 << NEONSize_offset) : 0;
  Emit(format | NEON_FCVTL | Rn(vn) | Rd(vd));
}

void Assembler::fcvtl2(const VRegister& vd, const VRegister& vn) {
  DCHECK((vd.Is4S() && vn.Is8H()) || (vd.Is2D() && vn.Is4S()));
  Instr format = vd.Is2D() ? (1 << NEONSize_offset) : 0;
  Emit(NEON_Q | format | NEON_FCVTL | Rn(vn) | Rd(vd));
}

void Assembler::fcvtn(const VRegister& vd, const VRegister& vn) {
  DCHECK((vn.Is4S() && vd.Is4H()) || (vn.Is2D() && vd.Is2S()));
  Instr format = vn.Is2D() ? (1 << NEONSize_offset) : 0;
  Emit(format | NEON_FCVTN | Rn(vn) | Rd(vd));
}

void Assembler::fcvtn2(const VRegister& vd, const VRegister& vn) {
  DCHECK((vn.Is4S() && vd.Is8H()) || (vn.Is2D() && vd.Is4S()));
  Instr format = vn.Is2D() ? (1 << NEONSize_offset) : 0;
  Emit(NEON_Q | format | NEON_FCVTN | Rn(vn) | Rd(vd));
}

void Assembler::fcvtxn(const VRegister& vd, const VRegister& vn) {
  Instr format = 1 << NEONSize_offset;
  if (vd.IsScalar()) {
    DCHECK(vd.Is1S() && vn.Is1D());
    Emit(format | NEON_FCVTXN_scalar | Rn(vn) | Rd(vd));
  } else {
    DCHECK(vd.Is2S() && vn.Is2D());
    Emit(format | NEON_FCVTXN | Rn(vn) | Rd(vd));
  }
}

void Assembler::fcvtxn2(const VRegister& vd, const VRegister& vn) {
  DCHECK(vd.Is4S() && vn.Is2D());
  Instr format = 1 << NEONSize_offset;
  Emit(NEON_Q | format | NEON_FCVTXN | Rn(vn) | Rd(vd));
}

void Assembler::fjcvtzs(const Register& rd, const VRegister& vn) {
  DCHECK(rd.IsW() && vn.Is1D());
  Emit(FJCVTZS | Rn(vn) | Rd(rd));
}

#define NEON_FP2REGMISC_FCVT_LIST(V) \
  V(fcvtnu, NEON_FCVTNU, FCVTNU)     \
  V(fcvtns, NEON_FCVTNS, FCVTNS)     \
  V(fcvtpu, NEON_FCVTPU, FCVTPU)     \
  V(fcvtps, NEON_FCVTPS, FCVTPS)     \
  V(fcvtmu, NEON_FCVTMU, FCVTMU)     \
  V(fcvtms, NEON_FCVTMS, FCVTMS)     \
  V(fcvtau, NEON_FCVTAU, FCVTAU)     \
  V(fcvtas, NEON_FCVTAS, FCVTAS)

#define DEFINE_ASM_FUNCS(FN, VEC_OP, SCA_OP)                     \
  void Assembler::FN(const Register& rd, const VRegister& vn) {  \
    NEONFPConvertToInt(rd, vn, SCA_OP);                          \
  }                                                              \
  void Assembler::FN(const VRegister& vd, const VRegister& vn) { \
    NEONFPConvertToInt(vd, vn, VEC_OP);                          \
  }
NEON_FP2REGMISC_FCVT_LIST(DEFINE_ASM_FUNCS)
#undef DEFINE_ASM_FUNCS

void Assembler::scvtf(const VRegister& vd, const VRegister& vn, int fbits) {
  DCHECK_GE(fbits, 0);
  if (fbits == 0) {
    NEONFP2RegMisc(vd, vn, NEON_SCVTF, 0.0);
  } else {
    DCHECK(vd.Is1D() || vd.Is1S() || vd.Is2D() || vd.Is2S() || vd.Is4S());
    NEONShiftRightImmediate(vd, vn, fbits, NEON_SCVTF_imm);
  }
}

void Assembler::ucvtf(const VRegister& vd, const VRegister& vn, int fbits) {
  DCHECK_GE(fbits, 0);
  if (fbits == 0) {
    NEONFP2RegMisc(vd, vn, NEON_UCVTF, 0.0);
  } else {
    DCHECK(vd.Is1D() || vd.Is1S() || vd.Is2D() || vd.Is2S() || vd.Is4S());
    NEONShiftRightImmediate(vd, vn, fbits, NEON_UCVTF_imm);
  }
}

void Assembler::scvtf(const VRegister& vd, const Register& rn, int fbits) {
  DCHECK_GE(fbits, 0);
  if (fbits == 0) {
    Emit(SF(rn) | FPType(vd) | SCVTF | Rn(rn) | Rd(vd));
  } else {
    Emit(SF(rn) | FPType(vd) | SCVTF_fixed | FPScale(64 - fbits) | Rn(rn) |
         Rd(vd));
  }
}

void Assembler::ucvtf(const VRegister& fd, const Register& rn, int fbits) {
  DCHECK_GE(fbits, 0);
  if (fbits == 0) {
    Emit(SF(rn) | FPType(fd) | UCVTF | Rn(rn) | Rd(fd));
  } else {
    Emit(SF(rn) | FPType(fd) | UCVTF_fixed | FPScale(64 - fbits) | Rn(rn) |
         Rd(fd));
  }
}

void Assembler::NEON3Same(const VRegister& vd, const VRegister& vn,
                          const VRegister& vm, NEON3SameOp vop) {
  DCHECK(AreSameFormat(vd, vn, vm));
  DCHECK(vd.IsVector() || !vd.IsQ());

  Instr format, op = vop;
  if (vd.IsScalar()) {
    op |= NEON_Q | NEONScalar;
    format = SFormat(vd);
  } else {
    format = VFormat(vd);
  }

  Emit(format | op | Rm(vm) | Rn(vn) | Rd(vd));
}

void Assembler::NEONFP3Same(const VRegister& vd, const VRegister& vn,
                            const VRegister& vm, Instr op) {
  DCHECK(AreSameFormat(vd, vn, vm));
  if (vd.Is4H() || vd.Is8H()) {
    op |= NEON_sz;
    op ^= NEON3SameHPMask;
  }
  Emit(FPFormat(vd) | op | Rm(vm) | Rn(vn) | Rd(vd));
}

#define NEON_FP2REGMISC_LIST(V)                 \
  V(fabs, NEON_FABS, FABS)                      \
  V(fneg, NEON_FNEG, FNEG)                      \
  V(fsqrt, NEON_FSQRT, FSQRT)                   \
  V(frintn, NEON_FRINTN, FRINTN)                \
  V(frinta, NEON_FRINTA, FRINTA)                \
  V(frintp, NEON_FRINTP, FRINTP)                \
  V(frintm, NEON_FRINTM, FRINTM)                \
  V(frintx, NEON_FRINTX, FRINTX)                \
  V(frintz, NEON_FRINTZ, FRINTZ)                \
  V(frinti, NEON_FRINTI, FRINTI)                \
  V(frsqrte, NEON_FRSQRTE, NEON_FRSQRTE_scalar) \
  V(frecpe, NEON_FRECPE, NEON_FRECPE_scalar)

#define DEFINE_ASM_FUNC(FN, VEC_OP, SCA_OP)                      \
  void Assembler::FN(const VRegister& vd, const VRegister& vn) { \
    if (vd.IsScalar()) {                                         \
      DCHECK(vd.Is1S() || vd.Is1D());                            \
      NEONFP2RegMisc(vd, vn, SCA_OP);                            \
    } else {                                                     \
      NEONFP2RegMisc(vd, vn, VEC_OP, 0.0);                       \
    }                                                            \
  }
NEON_FP2REGMISC_LIST(DEFINE_ASM_FUNC)
#undef DEFINE_ASM_FUNC

void Assembler::shll(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK((vd.Is8H() && vn.Is8B() && shift == 8) ||
         (vd.Is4S() && vn.Is4H() && shift == 16) ||
         (vd.Is2D() && vn.Is2S() && shift == 32));
  USE(shift);
  Emit(VFormat(vn) | NEON_SHLL | Rn(vn) | Rd(vd));
}

void Assembler::shll2(const VRegister& vd, const VRegister& vn, int shift) {
  USE(shift);
  DCHECK((vd.Is8H() && vn.Is16B() && shift == 8) ||
         (vd.Is4S() && vn.Is8H() && shift == 16) ||
         (vd.Is2D() && vn.Is4S() && shift == 32));
  Emit(VFormat(vn) | NEON_SHLL | Rn(vn) | Rd(vd));
}

void Assembler::NEONFP2RegMisc(const VRegister& vd, const VRegister& vn,
                               NEON2RegMiscOp vop, double value) {
  DCHECK(AreSameFormat(vd, vn));
  DCHECK_EQ(value, 0.0);
  USE(value);

  Instr op = vop;
  if (vd.IsScalar()) {
    DCHECK(vd.Is1S() || vd.Is1D());
    op |= NEON_Q | NEONScalar;
  } else if (vd.Is4H() || vd.Is8H()) {
    op |= NEON_sz | NEON2RegMiscHPFixed;
  } else {
    DCHECK(vd.Is2S() || vd.Is2D() || vd.Is4S());
  }

  Emit(FPFormat(vd) | op | Rn(vn) | Rd(vd));
}

void Assembler::fcmeq(const VRegister& vd, const VRegister& vn, double value) {
  NEONFP2RegMisc(vd, vn, NEON_FCMEQ_zero, value);
}

void Assembler::fcmge(const VRegister& vd, const VRegister& vn, double value) {
  NEONFP2RegMisc(vd, vn, NEON_FCMGE_zero, value);
}

void Assembler::fcmgt(const VRegister& vd, const VRegister& vn, double value) {
  NEONFP2RegMisc(vd, vn, NEON_FCMGT_zero, value);
}

void Assembler::fcmle(const VRegister& vd, const VRegister& vn, double value) {
  NEONFP2RegMisc(vd, vn, NEON_FCMLE_zero, value);
}

void Assembler::fcmlt(const VRegister& vd, const VRegister& vn, double value) {
  NEONFP2RegMisc(vd, vn, NEON_FCMLT_zero, value);
}

void Assembler::frecpx(const VRegister& vd, const VRegister& vn) {
  DCHECK(vd.IsScalar());
  DCHECK(AreSameFormat(vd, vn));
  DCHECK(vd.Is1S() || vd.Is1D());
  Emit(FPFormat(vd) | NEON_FRECPX_scalar | Rn(vn) | Rd(vd));
}

void Assembler::fcvtzs(const Register& rd, const VRegister& vn, int fbits) {
  DCHECK(vn.Is1S() || vn.Is1D());
  DCHECK((fbits >= 0) && (fbits <= rd.SizeInBits()));
  if (fbits == 0) {
    Emit(SF(rd) | FPType(vn) | FCVTZS | Rn(vn) | Rd(rd));
  } else {
    Emit(SF(rd) | FPType(vn) | FCVTZS_fixed | FPScale(64 - fbits) | Rn(vn) |
         Rd(rd));
  }
}

void Assembler::fcvtzs(const VRegister& vd, const VRegister& vn, int fbits) {
  DCHECK_GE(fbits, 0);
  if (fbits == 0) {
    NEONFP2RegMisc(vd, vn, NEON_FCVTZS, 0.0);
  } else {
    DCHECK(vd.Is1D() || vd.Is1S() || vd.Is2D() || vd.Is2S() || vd.Is4S());
    NEONShiftRightImmediate(vd, vn, fbits, NEON_FCVTZS_imm);
  }
}

void Assembler::fcvtzu(const Register& rd, const VRegister& vn, int fbits) {
  DCHECK(vn.Is1S() || vn.Is1D());
  DCHECK((fbits >= 0) && (fbits <= rd.SizeInBits()));
  if (fbits == 0) {
    Emit(SF(rd) | FPType(vn) | FCVTZU | Rn(vn) | Rd(rd));
  } else {
    Emit(SF(rd) | FPType(vn) | FCVTZU_fixed | FPScale(64 - fbits) | Rn(vn) |
         Rd(rd));
  }
}

void Assembler::fcvtzu(const VRegister& vd, const VRegister& vn, int fbits) {
  DCHECK_GE(fbits, 0);
  if (fbits == 0) {
    NEONFP2RegMisc(vd, vn, NEON_FCVTZU, 0.0);
  } else {
    DCHECK(vd.Is1D() || vd.Is1S() || vd.Is2D() || vd.Is2S() || vd.Is4S());
    NEONShiftRightImmediate(vd, vn, fbits, NEON_FCVTZU_imm);
  }
}

void Assembler::NEONFP2RegMisc(const VRegister& vd, const VRegister& vn,
                               Instr op) {
  DCHECK(AreSameFormat(vd, vn));
  Emit(FPFormat(vd) | op | Rn(vn) | Rd(vd));
}

void Assembler::NEON2RegMisc(const VRegister& vd, const VRegister& vn,
                             NEON2RegMiscOp vop, int value) {
  DCHECK(AreSameFormat(vd, vn));
  DCHECK_EQ(value, 0);
  USE(value);

  Instr format, op = vop;
  if (vd.IsScalar()) {
    op |= NEON_Q | NEONScalar;
    format = SFormat(vd);
  } else {
    format = VFormat(vd);
  }

  Emit(format | op | Rn(vn) | Rd(vd));
}

void Assembler::cmeq(const VRegister& vd, const VRegister& vn, int value) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEON2RegMisc(vd, vn, NEON_CMEQ_zero, value);
}

void Assembler::cmge(const VRegister& vd, const VRegister& vn, int value) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEON2RegMisc(vd, vn, NEON_CMGE_zero, value);
}

void Assembler::cmgt(const VRegister& vd, const VRegister& vn, int value) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEON2RegMisc(vd, vn, NEON_CMGT_zero, value);
}

void Assembler::cmle(const VRegister& vd, const VRegister& vn, int value) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEON2RegMisc(vd, vn, NEON_CMLE_zero, value);
}

void Assembler::cmlt(const VRegister& vd, const VRegister& vn, int value) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEON2RegMisc(vd, vn, NEON_CMLT_zero, value);
}

#define NEON_3SAME_LIST(V)                                         \
  V(add, NEON_ADD, vd.IsVector() || vd.Is1D())                     \
  V(addp, NEON_ADDP, vd.IsVector() || vd.Is1D())                   \
  V(sub, NEON_SUB, vd.IsVector() || vd.Is1D())                     \
  V(cmeq, NEON_CMEQ, vd.IsVector() || vd.Is1D())                   \
  V(cmge, NEON_CMGE, vd.IsVector() || vd.Is1D())                   \
  V(cmgt, NEON_CMGT, vd.IsVector() || vd.Is1D())                   \
  V(cmhi, NEON_CMHI, vd.IsVector() || vd.Is1D())                   \
  V(cmhs, NEON_CMHS, vd.IsVector() || vd.Is1D())                   \
  V(cmtst, NEON_CMTST, vd.IsVector() || vd.Is1D())                 \
  V(sshl, NEON_SSHL, vd.IsVector() || vd.Is1D())                   \
  V(ushl, NEON_USHL, vd.IsVector() || vd.Is1D())                   \
  V(srshl, NEON_SRSHL, vd.IsVector() || vd.Is1D())                 \
  V(urshl, NEON_URSHL, vd.IsVector() || vd.Is1D())                 \
  V(sqdmulh, NEON_SQDMULH, vd.IsLaneSizeH() || vd.IsLaneSizeS())   \
  V(sqrdmulh, NEON_SQRDMULH, vd.IsLaneSizeH() || vd.IsLaneSizeS()) \
  V(shadd, NEON_SHADD, vd.IsVector() && !vd.IsLaneSizeD())         \
  V(uhadd, NEON_UHADD, vd.IsVector() && !vd.IsLaneSizeD())         \
  V(srhadd, NEON_SRHADD, vd.IsVector() && !vd.IsLaneSizeD())       \
  V(urhadd, NEON_URHADD, vd.IsVector() && !vd.IsLaneSizeD())       \
  V(shsub, NEON_SHSUB, vd.IsVector() && !vd.IsLaneSizeD())         \
  V(uhsub, NEON_UHSUB, vd.IsVector() && !vd.IsLaneSizeD())         \
  V(smax, NEON_SMAX, vd.IsVector() && !vd.IsLaneSizeD())           \
  V(smaxp, NEON_SMAXP, vd.IsVector() && !vd.IsLaneSizeD())         \
  V(smin, NEON_SMIN, vd.IsVector() && !vd.IsLaneSizeD())           \
  V(sminp, NEON_SMINP, vd.IsVector() && !vd.IsLaneSizeD())         \
  V(umax, NEON_UMAX, vd.IsVector() && !vd.IsLaneSizeD())           \
  V(umaxp, NEON_UMAXP, vd.IsVector() && !vd.IsLaneSizeD())         \
  V(umin, NEON_UMIN, vd.IsVector() && !vd.IsLaneSizeD())           \
  V(uminp, NEON_UMINP, vd.IsVector() && !vd.IsLaneSizeD())         \
  V(saba, NEON_SABA, vd.IsVector() && !vd.IsLaneSizeD())           \
  V(sabd, NEON_SABD, vd.IsVector() && !vd.IsLaneSizeD())           \
  V(uaba, NEON_UABA, vd.IsVector() && !vd.IsLaneSizeD())           \
  V(uabd, NEON_UABD, vd.IsVector() && !vd.IsLaneSizeD())           \
  V(mla, NEON_MLA, vd.IsVector() && !vd.IsLaneSizeD())             \
  V(mls, NEON_MLS, vd.IsVector() && !vd.IsLaneSizeD())             \
  V(mul, NEON_MUL, vd.IsVector() && !vd.IsLaneSizeD())             \
  V(and_, NEON_AND, vd.Is8B() || vd.Is16B())                       \
  V(orr, NEON_ORR, vd.Is8B() || vd.Is16B())                        \
  V(orn, NEON_ORN, vd.Is8B() || vd.Is16B())                        \
  V(eor, NEON_EOR, vd.Is8B() || vd.Is16B())                        \
  V(bic, NEON_BIC, vd.Is8B() || vd.Is16B())                        \
  V(bit, NEON_BIT, vd.Is8B() || vd.Is16B())                        \
  V(bif, NEON_BIF, vd.Is8B() || vd.Is16B())                        \
  V(bsl, NEON_BSL, vd.Is8B() || vd.Is16B())                        \
  V(pmul, NEON_PMUL, vd.Is8B() || vd.Is16B())                      \
  V(uqadd, NEON_UQADD, true)                                       \
  V(sqadd, NEON_SQADD, true)                                       \
  V(uqsub, NEON_UQSUB, true)                                       \
  V(sqsub, NEON_SQSUB, true)                                       \
  V(sqshl, NEON_SQSHL, true)                                       \
  V(uqshl, NEON_UQSHL, true)                                       \
  V(sqrshl, NEON_SQRSHL, true)                                     \
  V(uqrshl, NEON_UQRSHL, true)

#define DEFINE_ASM_FUNC(FN, OP, AS)                            \
  void Assembler::FN(const VRegister& vd, const VRegister& vn, \
                     const VRegister& vm) {                    \
    DCHECK(AS);                                                \
    NEON3Same(vd, vn, vm, OP);                                 \
  }
NEON_3SAME_LIST(DEFINE_ASM_FUNC)
#undef DEFINE_ASM_FUNC

#define NEON_FP3SAME_LIST_V2(V)                 \
  V(fadd, NEON_FADD, FADD)                      \
  V(fsub, NEON_FSUB, FSUB)                      \
  V(fmul, NEON_FMUL, FMUL)                      \
  V(fdiv, NEON_FDIV, FDIV)                      \
  V(fmax, NEON_FMAX, FMAX)                      \
  V(fmaxnm, NEON_FMAXNM, FMAXNM)                \
  V(fmin, NEON_FMIN, FMIN)                      \
  V(fminnm, NEON_FMINNM, FMINNM)                \
  V(fmulx, NEON_FMULX, NEON_FMULX_scalar)       \
  V(frecps, NEON_FRECPS, NEON_FRECPS_scalar)    \
  V(frsqrts, NEON_FRSQRTS, NEON_FRSQRTS_scalar) \
  V(fabd, NEON_FABD, NEON_FABD_scalar)          \
  V(fmla, NEON_FMLA, 0)                         \
  V(fmls, NEON_FMLS, 0)                         \
  V(facge, NEON_FACGE, NEON_FACGE_scalar)       \
  V(facgt, NEON_FACGT, NEON_FACGT_scalar)       \
  V(fcmeq, NEON_FCMEQ, NEON_FCMEQ_scalar)       \
  V(fcmge, NEON_FCMGE, NEON_FCMGE_scalar)       \
  V(fcmgt, NEON_FCMGT, NEON_FCMGT_scalar)       \
  V(faddp, NEON_FADDP, 0)                       \
  V(fmaxp, NEON_FMAXP, 0)                       \
  V(fminp, NEON_FMINP, 0)                       \
  V(fmaxnmp, NEON_FMAXNMP, 0)                   \
  V(fminnmp, NEON_FMINNMP, 0)

#define DEFINE_ASM_FUNC(FN, VEC_OP, SCA_OP)                                  \
  void Assembler::FN(const VRegister& vd, const VRegister& vn,               \
                     const VRegister& vm) {                                  \
    Instr op;                                                                \
    if ((SCA_OP != 0) && vd.IsScalar()) {                                    \
      DCHECK(vd.Is1S() || vd.Is1D());                                        \
      op = SCA_OP;                                                           \
    } else {                                                                 \
      DCHECK(vd.IsVector());                                                 \
      DCHECK(vd.Is2S() || vd.Is2D() || vd.Is4S() || vd.Is4H() || vd.Is8H()); \
      op = VEC_OP;                                                           \
    }                                                                        \
    NEONFP3Same(vd, vn, vm, op);                                             \
  }
NEON_FP3SAME_LIST_V2(DEFINE_ASM_FUNC)
#undef DEFINE_ASM_FUNC

void Assembler::addp(const VRegister& vd, const VRegister& vn) {
  DCHECK((vd.Is1D() && vn.Is2D()));
  Emit(SFormat(vd) | NEON_ADDP_scalar | Rn(vn) | Rd(vd));
}

void Assembler::faddp(const VRegister& vd, const VRegister& vn) {
  DCHECK((vd.Is1S() && vn.Is2S()) || (vd.Is1D() && vn.Is2D()));
  Emit(FPFormat(vd) | NEON_FADDP_scalar | Rn(vn) | Rd(vd));
}

void Assembler::fmaxp(const VRegister& vd, const VRegister& vn) {
  DCHECK((vd.Is1S() && vn.Is2S()) || (vd.Is1D() && vn.Is2D()));
  Emit(FPFormat(vd) | NEON_FMAXP_scalar | Rn(vn) | Rd(vd));
}

void Assembler::fminp(const VRegister& vd, const VRegister& vn) {
  DCHECK((vd.Is1S() && vn.Is2S()) || (vd.Is1D() && vn.Is2D()));
  Emit(FPFormat(vd) | NEON_FMINP_scalar | Rn(vn) | Rd(vd));
}

void Assembler::fmaxnmp(const VRegister& vd, const VRegister& vn) {
  DCHECK((vd.Is1S() && vn.Is2S()) || (vd.Is1D() && vn.Is2D()));
  Emit(FPFormat(vd) | NEON_FMAXNMP_scalar | Rn(vn) | Rd(vd));
}

void Assembler::fminnmp(const VRegister& vd, const VRegister& vn) {
  DCHECK((vd.Is1S() && vn.Is2S()) || (vd.Is1D() && vn.Is2D()));
  Emit(FPFormat(vd) | NEON_FMINNMP_scalar | Rn(vn) | Rd(vd));
}

void Assembler::orr(const VRegister& vd, const int imm8, const int left_shift) {
  NEONModifiedImmShiftLsl(vd, imm8, left_shift, NEONModifiedImmediate_ORR);
}

void Assembler::mov(const VRegister& vd, const VRegister& vn) {
  DCHECK(AreSameFormat(vd, vn));
  if (vd.IsD()) {
    orr(vd.V8B(), vn.V8B(), vn.V8B());
  } else {
    DCHECK(vd.IsQ());
    orr(vd.V16B(), vn.V16B(), vn.V16B());
  }
}

void Assembler::bic(const VRegister& vd, const int imm8, const int left_shift) {
  NEONModifiedImmShiftLsl(vd, imm8, left_shift, NEONModifiedImmediate_BIC);
}

void Assembler::movi(const VRegister& vd, const uint64_t imm, Shift shift,
                     const int shift_amount) {
  DCHECK((shift == LSL) || (shift == MSL));
  if (vd.Is2D() || vd.Is1D()) {
    DCHECK_EQ(shift_amount, 0);
    int imm8 = 0;
    for (int i = 0; i < 8; ++i) {
      int byte = (imm >> (i * 8)) & 0xFF;
      DCHECK((byte == 0) || (byte == 0xFF));
      if (byte == 0xFF) {
        imm8 |= (1 << i);
      }
    }
    Instr q = vd.Is2D() ? NEON_Q : 0;
    Emit(q | NEONModImmOp(1) | NEONModifiedImmediate_MOVI |
         ImmNEONabcdefgh(imm8) | NEONCmode(0xE) | Rd(vd));
  } else if (shift == LSL) {
    DCHECK(is_uint8(imm));
    NEONModifiedImmShiftLsl(vd, static_cast<int>(imm), shift_amount,
                            NEONModifiedImmediate_MOVI);
  } else {
    DCHECK(is_uint8(imm));
    NEONModifiedImmShiftMsl(vd, static_cast<int>(imm), shift_amount,
                            NEONModifiedImmediate_MOVI);
  }
}

void Assembler::mvn(const VRegister& vd, const VRegister& vn) {
  DCHECK(AreSameFormat(vd, vn));
  if (vd.IsD()) {
    not_(vd.V8B(), vn.V8B());
  } else {
    DCHECK(vd.IsQ());
    not_(vd.V16B(), vn.V16B());
  }
}

void Assembler::mvni(const VRegister& vd, const int imm8, Shift shift,
                     const int shift_amount) {
  DCHECK((shift == LSL) || (shift == MSL));
  if (shift == LSL) {
    NEONModifiedImmShiftLsl(vd, imm8, shift_amount, NEONModifiedImmediate_MVNI);
  } else {
    NEONModifiedImmShiftMsl(vd, imm8, shift_amount, NEONModifiedImmediate_MVNI);
  }
}

void Assembler::NEONFPByElement(const VRegister& vd, const VRegister& vn,
                                const VRegister& vm, int vm_index,
                                NEONByIndexedElementOp vop) {
  DCHECK(AreSameFormat(vd, vn));
  DCHECK((vd.Is2S() && vm.Is1S()) || (vd.Is4S() && vm.Is1S()) ||
         (vd.Is1S() && vm.Is1S()) || (vd.Is2D() && vm.Is1D()) ||
         (vd.Is1D() && vm.Is1D()));
  DCHECK((vm.Is1S() && (vm_index < 4)) || (vm.Is1D() && (vm_index < 2)));

  Instr op = vop;
  int index_num_bits = vm.Is1S() ? 2 : 1;
  if (vd.IsScalar()) {
    op |= NEON_Q | NEONScalar;
  }

  Emit(FPFormat(vd) | op | ImmNEONHLM(vm_index, index_num_bits) | Rm(vm) |
       Rn(vn) | Rd(vd));
}

void Assembler::NEONByElement(const VRegister& vd, const VRegister& vn,
                              const VRegister& vm, int vm_index,
                              NEONByIndexedElementOp vop) {
  DCHECK(AreSameFormat(vd, vn));
  DCHECK((vd.Is4H() && vm.Is1H()) || (vd.Is8H() && vm.Is1H()) ||
         (vd.Is1H() && vm.Is1H()) || (vd.Is2S() && vm.Is1S()) ||
         (vd.Is4S() && vm.Is1S()) || (vd.Is1S() && vm.Is1S()));
  DCHECK((vm.Is1H() && (vm.code() < 16) && (vm_index < 8)) ||
         (vm.Is1S() && (vm_index < 4)));

  Instr format, op = vop;
  int index_num_bits = vm.Is1H() ? 3 : 2;
  if (vd.IsScalar()) {
    op |= NEONScalar | NEON_Q;
    format = SFormat(vn);
  } else {
    format = VFormat(vn);
  }
  Emit(format | op | ImmNEONHLM(vm_index, index_num_bits) | Rm(vm) | Rn(vn) |
       Rd(vd));
}

void Assembler::NEONByElementL(const VRegister& vd, const VRegister& vn,
                               const VRegister& vm, int vm_index,
                               NEONByIndexedElementOp vop) {
  DCHECK((vd.Is4S() && vn.Is4H() && vm.Is1H()) ||
         (vd.Is4S() && vn.Is8H() && vm.Is1H()) ||
         (vd.Is1S() && vn.Is1H() && vm.Is1H()) ||
         (vd.Is2D() && vn.Is2S() && vm.Is1S()) ||
         (vd.Is2D() && vn.Is4S() && vm.Is1S()) ||
         (vd.Is1D() && vn.Is1S() && vm.Is1S()));

  DCHECK((vm.Is1H() && (vm.code() < 16) && (vm_index < 8)) ||
         (vm.Is1S() && (vm_index < 4)));

  Instr format, op = vop;
  int index_num_bits = vm.Is1H() ? 3 : 2;
  if (vd.IsScalar()) {
    op |= NEONScalar | NEON_Q;
    format = SFormat(vn);
  } else {
    format = VFormat(vn);
  }
  Emit(format | op | ImmNEONHLM(vm_index, index_num_bits) | Rm(vm) | Rn(vn) |
       Rd(vd));
}

#define NEON_BYELEMENT_LIST(V)              \
  V(mul, NEON_MUL_byelement, vn.IsVector()) \
  V(mla, NEON_MLA_byelement, vn.IsVector()) \
  V(mls, NEON_MLS_byelement, vn.IsVector()) \
  V(sqdmulh, NEON_SQDMULH_byelement, true)  \
  V(sqrdmulh, NEON_SQRDMULH_byelement, true)

#define DEFINE_ASM_FUNC(FN, OP, AS)                            \
  void Assembler::FN(const VRegister& vd, const VRegister& vn, \
                     const VRegister& vm, int vm_index) {      \
    DCHECK(AS);                                                \
    NEONByElement(vd, vn, vm, vm_index, OP);                   \
  }
NEON_BYELEMENT_LIST(DEFINE_ASM_FUNC)
#undef DEFINE_ASM_FUNC

#define NEON_FPBYELEMENT_LIST(V) \
  V(fmul, NEON_FMUL_byelement)   \
  V(fmla, NEON_FMLA_byelement)   \
  V(fmls, NEON_FMLS_byelement)   \
  V(fmulx, NEON_FMULX_byelement)

#define DEFINE_ASM_FUNC(FN, OP)                                \
  void Assembler::FN(const VRegister& vd, const VRegister& vn, \
                     const VRegister& vm, int vm_index) {      \
    NEONFPByElement(vd, vn, vm, vm_index, OP);                 \
  }
NEON_FPBYELEMENT_LIST(DEFINE_ASM_FUNC)
#undef DEFINE_ASM_FUNC

#define NEON_BYELEMENT_LONG_LIST(V)                              \
  V(sqdmull, NEON_SQDMULL_byelement, vn.IsScalar() || vn.IsD())  \
  V(sqdmull2, NEON_SQDMULL_byelement, vn.IsVector() && vn.IsQ()) \
  V(sqdmlal, NEON_SQDMLAL_byelement, vn.IsScalar() || vn.IsD())  \
  V(sqdmlal2, NEON_SQDMLAL_byelement, vn.IsVector() && vn.IsQ()) \
  V(sqdmlsl, NEON_SQDMLSL_byelement, vn.IsScalar() || vn.IsD())  \
  V(sqdmlsl2, NEON_SQDMLSL_byelement, vn.IsVector() && vn.IsQ()) \
  V(smull, NEON_SMULL_byelement, vn.IsVector() && vn.IsD())      \
  V(smull2, NEON_SMULL_byelement, vn.IsVector() && vn.IsQ())     \
  V(umull, NEON_UMULL_byelement, vn.IsVector() && vn.IsD())      \
  V(umull2, NEON_UMULL_byelement, vn.IsVector() && vn.IsQ())     \
  V(smlal, NEON_SMLAL_byelement, vn.IsVector() && vn.IsD())      \
  V(smlal2, NEON_SMLAL_byelement, vn.IsVector() && vn.IsQ())     \
  V(umlal, NEON_UMLAL_byelement, vn.IsVector() && vn.IsD())      \
  V(umlal2, NEON_UMLAL_byelement, vn.IsVector() && vn.IsQ())     \
  V(smlsl, NEON_SMLSL_byelement, vn.IsVector() && vn.IsD())      \
  V(smlsl2, NEON_SMLSL_byelement, vn.IsVector() && vn.IsQ())     \
  V(umlsl, NEON_UMLSL_byelement, vn.IsVector() && vn.IsD())      \
  V(umlsl2, NEON_UMLSL_byelement, vn.IsVector() && vn.IsQ())

#define DEFINE_ASM_FUNC(FN, OP, AS)                            \
  void Assembler::FN(const VRegister& vd, const VRegister& vn, \
                     const VRegister& vm, int vm_index) {      \
    DCHECK(AS);                                                \
    NEONByElementL(vd, vn, vm, vm_index, OP);                  \
  }
NEON_BYELEMENT_LONG_LIST(DEFINE_ASM_FUNC)
#undef DEFINE_ASM_FUNC

void Assembler::suqadd(const VRegister& vd, const VRegister& vn) {
  NEON2RegMisc(vd, vn, NEON_SUQADD);
}

void Assembler::usqadd(const VRegister& vd, const VRegister& vn) {
  NEON2RegMisc(vd, vn, NEON_USQADD);
}

void Assembler::abs(const VRegister& vd, const VRegister& vn) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEON2RegMisc(vd, vn, NEON_ABS);
}

void Assembler::sqabs(const VRegister& vd, const VRegister& vn) {
  NEON2RegMisc(vd, vn, NEON_SQABS);
}

void Assembler::neg(const VRegister& vd, const VRegister& vn) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEON2RegMisc(vd, vn, NEON_NEG);
}

void Assembler::sqneg(const VRegister& vd, const VRegister& vn) {
  NEON2RegMisc(vd, vn, NEON_SQNEG);
}

void Assembler::NEONXtn(const VRegister& vd, const VRegister& vn,
                        NEON2RegMiscOp vop) {
  Instr format, op = vop;
  if (vd.IsScalar()) {
    DCHECK((vd.Is1B() && vn.Is1H()) || (vd.Is1H() && vn.Is1S()) ||
           (vd.Is1S() && vn.Is1D()));
    op |= NEON_Q | NEONScalar;
    format = SFormat(vd);
  } else {
    DCHECK((vd.Is8B() && vn.Is8H()) || (vd.Is4H() && vn.Is4S()) ||
           (vd.Is2S() && vn.Is2D()) || (vd.Is16B() && vn.Is8H()) ||
           (vd.Is8H() && vn.Is4S()) || (vd.Is4S() && vn.Is2D()));
    format = VFormat(vd);
  }
  Emit(format | op | Rn(vn) | Rd(vd));
}

void Assembler::xtn(const VRegister& vd, const VRegister& vn) {
  DCHECK(vd.IsVector() && vd.IsD());
  NEONXtn(vd, vn, NEON_XTN);
}

void Assembler::xtn2(const VRegister& vd, const VRegister& vn) {
  DCHECK(vd.IsVector() && vd.IsQ());
  NEONXtn(vd, vn, NEON_XTN);
}

void Assembler::sqxtn(const VRegister& vd, const VRegister& vn) {
  DCHECK(vd.IsScalar() || vd.IsD());
  NEONXtn(vd, vn, NEON_SQXTN);
}

void Assembler::sqxtn2(const VRegister& vd, const VRegister& vn) {
  DCHECK(vd.IsVector() && vd.IsQ());
  NEONXtn(vd, vn, NEON_SQXTN);
}

void Assembler::sqxtun(const VRegister& vd, const VRegister& vn) {
  DCHECK(vd.IsScalar() || vd.IsD());
  NEONXtn(vd, vn, NEON_SQXTUN);
}

void Assembler::sqxtun2(const VRegister& vd, const VRegister& vn) {
  DCHECK(vd.IsVector() && vd.IsQ());
  NEONXtn(vd, vn, NEON_SQXTUN);
}

void Assembler::uqxtn(const VRegister& vd, const VRegister& vn) {
  DCHECK(vd.IsScalar() || vd.IsD());
  NEONXtn(vd, vn, NEON_UQXTN);
}

void Assembler::uqxtn2(const VRegister& vd, const VRegister& vn) {
  DCHECK(vd.IsVector() && vd.IsQ());
  NEONXtn(vd, vn, NEON_UQXTN);
}

// NEON NOT and RBIT are distinguised by bit 22, the bottom bit of "size".
void Assembler::not_(const VRegister& vd, const VRegister& vn) {
  DCHECK(AreSameFormat(vd, vn));
  DCHECK(vd.Is8B(
"""


```