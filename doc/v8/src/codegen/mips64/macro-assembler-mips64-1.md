Response: The user wants a summary of the functionality of the provided C++ code snippet. This snippet is part 2 of 4 of a larger file, `v8/src/codegen/mips64/macro-assembler-mips64.cc`. It seems to be focused on implementing various low-level operations for the MIPS64 architecture within the V8 JavaScript engine.

Here's a breakdown of the code's structure and likely purpose:

1. **Floating-Point Conversions:** The code starts with functions like `Cvt_d_uw`, `Cvt_d_ul`, `Cvt_s_uw`, `Cvt_s_ul`. These likely handle conversions between different integer and floating-point types (double and single-precision) on the MIPS64 FPU (Floating-Point Unit). The `uw` and `ul` suffixes likely indicate unsigned word (32-bit) and unsigned long (64-bit) integers, respectively.

2. **Floating-Point Rounding and Truncation:**  Functions like `Round_l_d`, `Floor_l_d`, `Ceil_l_d`, `Trunc_l_d`, `Trunc_uw_d`, etc., suggest implementations of different rounding and truncation modes for floating-point numbers. These are essential for correctly handling number conversions and mathematical operations according to language specifications (like IEEE 754).

3. **MSA (MIPS SIMD Architecture) Operations:**  The presence of functions like `LoadLane`, `StoreLane`, `ExtMulLow`, `ExtMulHigh`, `LoadSplat`, `ExtAddPairwise`, `MSARoundW`, `MSARoundD` indicates that this section also includes code for working with MIPS's SIMD (Single Instruction, Multiple Data) extensions. SIMD allows for performing the same operation on multiple data elements simultaneously, which can significantly speed up certain computations.

4. **More Floating-Point Arithmetic:** Functions like `Madd_s`, `Madd_d`, `Msub_s`, `Msub_d` suggest fused multiply-add/subtract operations, which can be more efficient than separate multiply and add/subtract instructions.

5. **Floating-Point Comparisons and Branching:**  The `CompareF`, `CompareIsNanF`, `BranchTrueShortF`, `BranchFalseShortF`, `BranchTrueF`, `BranchFalseF`, `BranchMSA`, `BranchShortMSA` functions deal with comparing floating-point numbers and conditionally branching based on the comparison results. This is fundamental for control flow in compiled code.

6. **Data Movement:** Functions like `FmoveLow`, `Move` (for both 32-bit and 64-bit immediate values), `Movz`, `Movn`, `LoadZeroIfConditionNotZero`, `LoadZeroIfConditionZero`, `Movt`, `Movf` handle moving data between registers and loading immediate values.

7. **Bit Manipulation:**  Functions like `Clz`, `Dclz`, `Ctz`, `Dctz`, `Popcnt`, `Dpopcnt` implement bit counting and manipulation operations. These are often used in low-level algorithms and optimizations.

8. **Double to Integer Conversion:** `TryInlineTruncateDoubleToI` and `TruncateDoubleToI` handle the potentially complex process of converting double-precision floating-point numbers to integers, taking care of overflow and NaN (Not-a-Number) cases.

9. **General Register Comparisons:** `CompareWord` implements comparisons between general-purpose registers, setting flags or a destination register based on the outcome.

10. **Conditional Branching (General Purpose Registers):**  The `Branch` family of functions (with variations like `BranchShort`, `BranchAndLink`, etc.) are crucial for control flow. They implement conditional jumps based on the state of general-purpose registers. The `BranchAndLink` versions are used for function calls, storing the return address.

11. **Loading and Storing Constants and Roots:** `LoadFromConstantsTable`, `LoadRootRelative`, `StoreRootRelative`, `LoadRootRegisterOffset` are used for accessing constant values and special runtime data (roots) within the V8 engine.

**Relationship to JavaScript:**

This code directly relates to how JavaScript code is executed. When the V8 engine compiles JavaScript, it translates JavaScript operations into sequences of machine instructions, many of which are implemented by the functions in this file.

**JavaScript Examples:**

* **Floating-Point Conversion:**
   ```javascript
   let x = 10;
   let y = parseFloat(x); // JavaScript's parseFloat would involve code similar to Cvt_d_uw if x was an integer.
   ```

* **Floating-Point Rounding/Truncation:**
   ```javascript
   let a = 10.5;
   let b = Math.floor(a); // Math.floor would likely use a function like Floor_l_d internally.
   let c = Math.trunc(a); // Math.trunc would likely use a function like Trunc_l_d.
   ```

* **SIMD Operations (if using a JavaScript SIMD API, not common in basic JS):**
   ```javascript
   // Hypothetical SIMD API in JavaScript
   let vector1 = new SIMD.Float32x4(1, 2, 3, 4);
   let vector2 = new SIMD.Float32x4(5, 6, 7, 8);
   let result = SIMD.add(vector1, vector2); // This operation would be implemented using MSA instructions.
   ```

* **Double to Integer Conversion:**
   ```javascript
   let d = 1e9;
   let e = parseInt(d); // parseInt would use logic similar to TruncateDoubleToI.
   ```

* **Conditional Logic:**
   ```javascript
   let num1 = 5;
   let num2 = 10;
   if (num1 < num2) { // This 'if' statement would translate to branch instructions based on a comparison.
       console.log("num1 is less than num2");
   }
   ```

In essence, this C++ code provides the fundamental building blocks for executing JavaScript's numerical and control flow operations on the MIPS64 architecture. It's a low-level implementation detail that enables the high-level abstractions of JavaScript.
This part of the `macro-assembler-mips64.cc` file in V8 focuses on implementing various **type conversion and rounding operations** specifically for floating-point numbers, along with some **conditional move and bit manipulation instructions**. It also includes implementations for **SIMD (MSA) operations** and **conditional branching**.

Here's a breakdown of the functionalities:

**Floating-Point Conversions and Rounding:**

* **Conversion from Integers to Floating-Point:**
    * `Cvt_d_uw(FPURegister fd, FPURegister fs)` and `Cvt_d_uw(FPURegister fd, Register rs)`: Converts an **unsigned word (32-bit integer)** to a **double-precision floating-point number**.
    * `Cvt_d_ul(FPURegister fd, FPURegister fs)` and `Cvt_d_ul(FPURegister fd, Register rs)`: Converts an **unsigned long (64-bit integer)** to a **double-precision floating-point number**. This includes special handling for numbers greater than or equal to 2^63.
    * `Cvt_s_uw(FPURegister fd, FPURegister fs)` and `Cvt_s_uw(FPURegister fd, Register rs)`: Converts an **unsigned word (32-bit integer)** to a **single-precision floating-point number**.
    * `Cvt_s_ul(FPURegister fd, FPURegister fs)` and `Cvt_s_ul(FPURegister fd, Register rs)`: Converts an **unsigned long (64-bit integer)** to a **single-precision floating-point number**. Similar to the double-precision version, it handles numbers >= 2^31.
* **Rounding and Truncation of Floating-Point Numbers:**
    * `Round_l_d`, `Floor_l_d`, `Ceil_l_d`, `Trunc_l_d`: Round a **double-precision** floating-point number to a **long integer** using different rounding modes (round to nearest, floor, ceiling, truncate).
    * `Trunc_l_ud`: Truncates a **double-precision** floating-point number to an **unsigned long integer**.
    * `Trunc_uw_d`, `Trunc_uw_s`: Truncates a **double-precision** or **single-precision** floating-point number to an **unsigned word (32-bit integer)**, handling values greater than 2^32.
    * `Trunc_ul_d`, `Trunc_ul_s`: Truncates a **double-precision** or **single-precision** floating-point number to an **unsigned long (64-bit integer)**, handling values greater than 2^63.
    * `Trunc_w_d`, `Round_w_d`, `Floor_w_d`, `Ceil_w_d`: Round a **double-precision** floating-point number to a **word integer** using different rounding modes.
* **Templated Rounding Functions:**
    * `RoundDouble`: A template function to implement different rounding modes for **double-precision** numbers. It checks if the number is within a certain range to perform direct rounding or uses specific rounding instructions.
    * `RoundFloat`: A template function similar to `RoundDouble` but for **single-precision** numbers.
    * Specific rounding functions like `Floor_d_d`, `Ceil_d_d`, `Trunc_d_d`, `Round_d_d` and their single-precision counterparts call these template functions.

**MSA (MIPS SIMD Architecture) Operations:**

* **Lane Load and Store:**
    * `LoadLane`: Loads a single element (byte, half-word, word, or double-word) from memory into a specific lane of an MSA register.
    * `StoreLane`: Stores a single element from a specific lane of an MSA register to memory.
* **Extended Multiply:**
    * `ExtMulLow`: Performs an extended multiplication of two MSA registers and stores the lower part of the result.
    * `ExtMulHigh`: Performs an extended multiplication of two MSA registers and stores the higher part of the result.
* **Load Splat:**
    * `LoadSplat`: Loads a single value from memory and replicates it across all lanes of an MSA register.
* **Pairwise Addition:**
    * `ExtAddPairwise`: Adds adjacent elements within an MSA register.
* **MSA Rounding:**
    * `MSARoundW`: Rounds the elements of an MSA register (containing single-precision floats) to the nearest integer based on the current rounding mode set in the MSA Control and Status Register (MSACSR).
    * `MSARoundD`: Similar to `MSARoundW` but for double-precision floats.

**More Floating-Point Arithmetic:**

* **Fused Multiply-Add/Subtract:**
    * `Madd_s`, `Madd_d`: Performs a fused multiply-add operation (fd = fr + fs * ft).
    * `Msub_s`, `Msub_d`: Performs a fused multiply-subtract operation (fd = fs * ft - fr).

**Floating-Point Comparisons and Branching:**

* **Comparison Instructions:**
    * `CompareF`: Compares two floating-point registers (single or double precision) and sets the FPU condition flag.
    * `CompareIsNanF`:  Compares if a floating-point number is NaN.
* **Conditional Branching based on FPU Flags:**
    * `BranchTrueShortF`, `BranchFalseShortF`: Branches to a target label if the FPU condition flag is true or false, respectively (short branch).
    * `BranchTrueF`, `BranchFalseF`:  Similar to the short versions, but handles long branches by potentially using a short branch to skip over a long jump.
* **Conditional Branching based on MSA Flags:**
    * `BranchMSA`: Branches based on the result of an MSA comparison.
    * `BranchShortMSA`: Performs a short branch based on MSA conditions.

**Conditional Moves and Bit Manipulation:**

* **Conditional Moves:**
    * `Movz`: Moves a value from one register to another if a third register is zero.
    * `Movn`: Moves a value if a third register is non-zero.
    * `LoadZeroIfConditionNotZero`: Loads zero into a register if a condition register is not zero.
    * `LoadZeroIfConditionZero`: Loads zero if a condition register is zero.
    * `LoadZeroIfFPUCondition`: Loads zero based on the FPU condition flag.
    * `LoadZeroIfNotFPUCondition`: Loads zero if the FPU condition flag is false.
    * `Movt`, `Movf`: Conditional move instructions based on a specific FPU condition code (pre-R6).
* **Bit Counting:**
    * `Clz`: Counts the number of leading zero bits in a word.
    * `Dclz`: Counts the number of leading zero bits in a double-word.
    * `Ctz`: Counts the number of trailing zero bits in a word (emulated for pre-R6).
    * `Dctz`: Counts the number of trailing zero bits in a double-word (emulated for pre-R6).
    * `Popcnt`: Counts the number of set bits (population count) in a word.
    * `Dpopcnt`: Counts the number of set bits in a double-word.

**Double to Integer Conversion (with potential Stub Call):**

* `TryInlineTruncateDoubleToI`: Attempts an inline conversion of a double to a signed integer.
* `TruncateDoubleToI`:  Performs a double to integer conversion. If the inline version fails (due to overflow or NaN), it calls a runtime stub (a pre-compiled function) to handle the conversion.

**General Register Comparisons:**

* `CompareWord`:  Compares two registers (or a register and an immediate value) and sets a destination register to 1 if the condition is true, and 0 otherwise.

**Conditional Branching (General Purpose Registers):**

* The `Branch` family of functions provides different ways to perform conditional jumps based on the values in general-purpose registers:
    * `Branch(int32_t offset, ...)`: Branches to a relative offset.
    * `Branch(Label* L, ...)`: Branches to a named label.
    * Different overloads allow specifying the condition for the branch (equal, not equal, greater than, etc.) and whether to execute an instruction in the branch delay slot (`BranchDelaySlot`).
    * `BranchShortHelper`, `BranchShortHelperR6`: Helper functions for generating short branch instructions, optimized for different MIPS architectures (R6 and pre-R6).
    * `BranchShortCheck`: Checks if a short branch can be used and calls the appropriate helper.
* `BranchAndLink`:  Similar to `Branch`, but also saves the return address in the `ra` (return address) register, used for function calls.

**Relationship to JavaScript:**

These low-level operations are fundamental to how the V8 JavaScript engine executes JavaScript code on MIPS64 architecture. When JavaScript code involves:

* **Number conversions:**  Operations like `Number()`, `parseInt()`, `parseFloat()`, or implicit type coercion would rely on these conversion functions.
* **Mathematical operations:**  Arithmetic operations, rounding functions (`Math.floor`, `Math.ceil`, `Math.round`, `Math.trunc`), would be implemented using these floating-point instructions.
* **SIMD operations (if the JavaScript code uses a SIMD API):** These MSA instructions would be used to accelerate parallel computations.
* **Conditional statements (`if`, `else if`, `else`):** The `Branch` instructions are essential for implementing control flow.
* **Function calls:** The `BranchAndLink` instructions are used to jump to function code while saving the return address.
* **Bitwise operations:**  Operators like `&`, `|`, `^`, `~`, `<<`, `>>`, `>>>` would utilize the bit manipulation instructions.

**In summary, this section of the code provides a comprehensive set of low-level primitives for handling numerical computations, type conversions, conditional execution, and SIMD operations on the MIPS64 architecture, which are essential for the efficient execution of JavaScript code within the V8 engine.**

Prompt: 
```
这是目录为v8/src/codegen/mips64/macro-assembler-mips64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
block_trampoline_pool(this);
  mfc1(t8, fs);
  Cvt_d_uw(fd, t8);
}

void MacroAssembler::Cvt_d_uw(FPURegister fd, Register rs) {
  BlockTrampolinePoolScope block_trampoline_pool(this);

  // Convert rs to a FP value in fd.
  DCHECK(rs != t9);
  DCHECK(rs != at);

  // Zero extend int32 in rs.
  Dext(t9, rs, 0, 32);
  dmtc1(t9, fd);
  cvt_d_l(fd, fd);
}

void MacroAssembler::Cvt_d_ul(FPURegister fd, FPURegister fs) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  // Move the data from fs to t8.
  dmfc1(t8, fs);
  Cvt_d_ul(fd, t8);
}

void MacroAssembler::Cvt_d_ul(FPURegister fd, Register rs) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  // Convert rs to a FP value in fd.

  DCHECK(rs != t9);
  DCHECK(rs != at);

  Label msb_clear, conversion_done;

  Branch(&msb_clear, ge, rs, Operand(zero_reg));

  // Rs >= 2^63
  andi(t9, rs, 1);
  dsrl(rs, rs, 1);
  or_(t9, t9, rs);
  dmtc1(t9, fd);
  cvt_d_l(fd, fd);
  Branch(USE_DELAY_SLOT, &conversion_done);
  add_d(fd, fd, fd);  // In delay slot.

  bind(&msb_clear);
  // Rs < 2^63, we can do simple conversion.
  dmtc1(rs, fd);
  cvt_d_l(fd, fd);

  bind(&conversion_done);
}

void MacroAssembler::Cvt_s_uw(FPURegister fd, FPURegister fs) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  // Move the data from fs to t8.
  mfc1(t8, fs);
  Cvt_s_uw(fd, t8);
}

void MacroAssembler::Cvt_s_uw(FPURegister fd, Register rs) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  // Convert rs to a FP value in fd.
  DCHECK(rs != t9);
  DCHECK(rs != at);

  // Zero extend int32 in rs.
  Dext(t9, rs, 0, 32);
  dmtc1(t9, fd);
  cvt_s_l(fd, fd);
}

void MacroAssembler::Cvt_s_ul(FPURegister fd, FPURegister fs) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  // Move the data from fs to t8.
  dmfc1(t8, fs);
  Cvt_s_ul(fd, t8);
}

void MacroAssembler::Cvt_s_ul(FPURegister fd, Register rs) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  // Convert rs to a FP value in fd.

  DCHECK(rs != t9);
  DCHECK(rs != at);

  Label positive, conversion_done;

  Branch(&positive, ge, rs, Operand(zero_reg));

  // Rs >= 2^31.
  andi(t9, rs, 1);
  dsrl(rs, rs, 1);
  or_(t9, t9, rs);
  dmtc1(t9, fd);
  cvt_s_l(fd, fd);
  Branch(USE_DELAY_SLOT, &conversion_done);
  add_s(fd, fd, fd);  // In delay slot.

  bind(&positive);
  // Rs < 2^31, we can do simple conversion.
  dmtc1(rs, fd);
  cvt_s_l(fd, fd);

  bind(&conversion_done);
}

void MacroAssembler::Round_l_d(FPURegister fd, FPURegister fs) {
  round_l_d(fd, fs);
}

void MacroAssembler::Floor_l_d(FPURegister fd, FPURegister fs) {
  floor_l_d(fd, fs);
}

void MacroAssembler::Ceil_l_d(FPURegister fd, FPURegister fs) {
  ceil_l_d(fd, fs);
}

void MacroAssembler::Trunc_l_d(FPURegister fd, FPURegister fs) {
  trunc_l_d(fd, fs);
}

void MacroAssembler::Trunc_l_ud(FPURegister fd, FPURegister fs,
                                FPURegister scratch) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  // Load to GPR.
  dmfc1(t8, fs);
  // Reset sign bit.
  {
    UseScratchRegisterScope temps(this);
    Register scratch1 = temps.Acquire();
    li(scratch1, 0x7FFFFFFFFFFFFFFF);
    and_(t8, t8, scratch1);
  }
  dmtc1(t8, fs);
  trunc_l_d(fd, fs);
}

void MacroAssembler::Trunc_uw_d(FPURegister fd, FPURegister fs,
                                FPURegister scratch) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Trunc_uw_d(t8, fs, scratch);
  mtc1(t8, fd);
}

void MacroAssembler::Trunc_uw_s(FPURegister fd, FPURegister fs,
                                FPURegister scratch) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Trunc_uw_s(t8, fs, scratch);
  mtc1(t8, fd);
}

void MacroAssembler::Trunc_ul_d(FPURegister fd, FPURegister fs,
                                FPURegister scratch, Register result) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Trunc_ul_d(t8, fs, scratch, result);
  dmtc1(t8, fd);
}

void MacroAssembler::Trunc_ul_s(FPURegister fd, FPURegister fs,
                                FPURegister scratch, Register result) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Trunc_ul_s(t8, fs, scratch, result);
  dmtc1(t8, fd);
}

void MacroAssembler::Trunc_w_d(FPURegister fd, FPURegister fs) {
  trunc_w_d(fd, fs);
}

void MacroAssembler::Round_w_d(FPURegister fd, FPURegister fs) {
  round_w_d(fd, fs);
}

void MacroAssembler::Floor_w_d(FPURegister fd, FPURegister fs) {
  floor_w_d(fd, fs);
}

void MacroAssembler::Ceil_w_d(FPURegister fd, FPURegister fs) {
  ceil_w_d(fd, fs);
}

void MacroAssembler::Trunc_uw_d(Register rd, FPURegister fs,
                                FPURegister scratch) {
  DCHECK(fs != scratch);
  DCHECK(rd != at);

  {
    // Load 2^32 into scratch as its float representation.
    UseScratchRegisterScope temps(this);
    Register scratch1 = temps.Acquire();
    li(scratch1, 0x41F00000);
    mtc1(zero_reg, scratch);
    mthc1(scratch1, scratch);
  }
  // Test if scratch > fd.
  // If fd < 2^32 we can convert it normally.
  Label simple_convert;
  CompareF64(ULT, fs, scratch);
  BranchTrueShortF(&simple_convert);

  // If fd > 2^32, the result should be UINT_32_MAX;
  Addu(rd, zero_reg, -1);

  Label done;
  Branch(&done);
  // Simple conversion.
  bind(&simple_convert);
  // Double -> Int64 -> Uint32;
  trunc_l_d(scratch, fs);
  mfc1(rd, scratch);

  bind(&done);
}

void MacroAssembler::Trunc_uw_s(Register rd, FPURegister fs,
                                FPURegister scratch) {
  DCHECK(fs != scratch);
  DCHECK(rd != at);

  {
    // Load 2^32 into scratch as its float representation.
    UseScratchRegisterScope temps(this);
    Register scratch1 = temps.Acquire();
    li(scratch1, 0x4F800000);
    mtc1(scratch1, scratch);
  }
  // Test if scratch > fs.
  // If fs < 2^32 we can convert it normally.
  Label simple_convert;
  CompareF32(ULT, fs, scratch);
  BranchTrueShortF(&simple_convert);

  // If fd > 2^32, the result should be UINT_32_MAX;
  Addu(rd, zero_reg, -1);

  Label done;
  Branch(&done);
  // Simple conversion.
  bind(&simple_convert);
  // Float -> Int64 -> Uint32;
  trunc_l_s(scratch, fs);
  mfc1(rd, scratch);

  bind(&done);
}

void MacroAssembler::Trunc_ul_d(Register rd, FPURegister fs,
                                FPURegister scratch, Register result) {
  DCHECK(fs != scratch);
  DCHECK(result.is_valid() ? !AreAliased(rd, result, at) : !AreAliased(rd, at));

  Label simple_convert, done, fail;
  if (result.is_valid()) {
    mov(result, zero_reg);
    Move(scratch, -1.0);
    // If fd =< -1 or unordered, then the conversion fails.
    CompareF64(ULE, fs, scratch);
    BranchTrueShortF(&fail);
  }

  // Load 2^63 into scratch as its double representation.
  li(at, 0x43E0000000000000);
  dmtc1(at, scratch);

  // Test if scratch > fs.
  // If fs < 2^63 or unordered, we can convert it normally.
  CompareF64(ULT, fs, scratch);
  BranchTrueShortF(&simple_convert);

  // First we subtract 2^63 from fs, then trunc it to rd
  // and add 2^63 to rd.
  sub_d(scratch, fs, scratch);
  trunc_l_d(scratch, scratch);
  dmfc1(rd, scratch);
  Or(rd, rd, Operand(1UL << 63));
  Branch(&done);

  // Simple conversion.
  bind(&simple_convert);
  trunc_l_d(scratch, fs);
  dmfc1(rd, scratch);

  bind(&done);
  if (result.is_valid()) {
    // Conversion is failed if the result is negative.
    {
      UseScratchRegisterScope temps(this);
      Register scratch1 = temps.Acquire();
      addiu(scratch1, zero_reg, -1);
      dsrl(scratch1, scratch1, 1);  // Load 2^62.
      dmfc1(result, scratch);
      xor_(result, result, scratch1);
    }
    Slt(result, zero_reg, result);
  }

  bind(&fail);
}

void MacroAssembler::Trunc_ul_s(Register rd, FPURegister fs,
                                FPURegister scratch, Register result) {
  DCHECK(fs != scratch);
  DCHECK(result.is_valid() ? !AreAliased(rd, result, at) : !AreAliased(rd, at));

  Label simple_convert, done, fail;
  if (result.is_valid()) {
    mov(result, zero_reg);
    Move(scratch, -1.0f);
    // If fd =< -1 or unordered, then the conversion fails.
    CompareF32(ULE, fs, scratch);
    BranchTrueShortF(&fail);
  }

  {
    // Load 2^63 into scratch as its float representation.
    UseScratchRegisterScope temps(this);
    Register scratch1 = temps.Acquire();
    li(scratch1, 0x5F000000);
    mtc1(scratch1, scratch);
  }

  // Test if scratch > fs.
  // If fs < 2^63 or unordered, we can convert it normally.
  CompareF32(ULT, fs, scratch);
  BranchTrueShortF(&simple_convert);

  // First we subtract 2^63 from fs, then trunc it to rd
  // and add 2^63 to rd.
  sub_s(scratch, fs, scratch);
  trunc_l_s(scratch, scratch);
  dmfc1(rd, scratch);
  Or(rd, rd, Operand(1UL << 63));
  Branch(&done);

  // Simple conversion.
  bind(&simple_convert);
  trunc_l_s(scratch, fs);
  dmfc1(rd, scratch);

  bind(&done);
  if (result.is_valid()) {
    // Conversion is failed if the result is negative or unordered.
    {
      UseScratchRegisterScope temps(this);
      Register scratch1 = temps.Acquire();
      addiu(scratch1, zero_reg, -1);
      dsrl(scratch1, scratch1, 1);  // Load 2^62.
      dmfc1(result, scratch);
      xor_(result, result, scratch1);
    }
    Slt(result, zero_reg, result);
  }

  bind(&fail);
}

template <typename RoundFunc>
void MacroAssembler::RoundDouble(FPURegister dst, FPURegister src,
                                 FPURoundingMode mode, RoundFunc round) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register scratch = t8;
  if (kArchVariant == kMips64r6) {
    cfc1(scratch, FCSR);
    li(at, Operand(mode));
    ctc1(at, FCSR);
    rint_d(dst, src);
    ctc1(scratch, FCSR);
  } else {
    Label done;
    if (!IsDoubleZeroRegSet()) {
      Move(kDoubleRegZero, 0.0);
    }
    mfhc1(scratch, src);
    Ext(at, scratch, HeapNumber::kExponentShift, HeapNumber::kExponentBits);
    Branch(USE_DELAY_SLOT, &done, hs, at,
           Operand(HeapNumber::kExponentBias + HeapNumber::kMantissaBits));
    mov_d(dst, src);

    round(this, dst, src);
    dmfc1(at, dst);
    Branch(USE_DELAY_SLOT, &done, ne, at, Operand(zero_reg));
    cvt_d_l(dst, dst);
    srl(at, scratch, 31);
    sll(at, at, 31);
    mthc1(at, dst);
    bind(&done);
  }
}

void MacroAssembler::Floor_d_d(FPURegister dst, FPURegister src) {
  RoundDouble(dst, src, mode_floor,
              [](MacroAssembler* masm, FPURegister dst, FPURegister src) {
                masm->floor_l_d(dst, src);
              });
}

void MacroAssembler::Ceil_d_d(FPURegister dst, FPURegister src) {
  RoundDouble(dst, src, mode_ceil,
              [](MacroAssembler* masm, FPURegister dst, FPURegister src) {
                masm->ceil_l_d(dst, src);
              });
}

void MacroAssembler::Trunc_d_d(FPURegister dst, FPURegister src) {
  RoundDouble(dst, src, mode_trunc,
              [](MacroAssembler* masm, FPURegister dst, FPURegister src) {
                masm->trunc_l_d(dst, src);
              });
}

void MacroAssembler::Round_d_d(FPURegister dst, FPURegister src) {
  RoundDouble(dst, src, mode_round,
              [](MacroAssembler* masm, FPURegister dst, FPURegister src) {
                masm->round_l_d(dst, src);
              });
}

template <typename RoundFunc>
void MacroAssembler::RoundFloat(FPURegister dst, FPURegister src,
                                FPURoundingMode mode, RoundFunc round) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register scratch = t8;
  if (kArchVariant == kMips64r6) {
    cfc1(scratch, FCSR);
    li(at, Operand(mode));
    ctc1(at, FCSR);
    rint_s(dst, src);
    ctc1(scratch, FCSR);
  } else {
    int32_t kFloat32ExponentBias = 127;
    int32_t kFloat32MantissaBits = 23;
    int32_t kFloat32ExponentBits = 8;
    Label done;
    if (!IsDoubleZeroRegSet()) {
      Move(kDoubleRegZero, 0.0);
    }
    mfc1(scratch, src);
    Ext(at, scratch, kFloat32MantissaBits, kFloat32ExponentBits);
    Branch(USE_DELAY_SLOT, &done, hs, at,
           Operand(kFloat32ExponentBias + kFloat32MantissaBits));
    mov_s(dst, src);

    round(this, dst, src);
    mfc1(at, dst);
    Branch(USE_DELAY_SLOT, &done, ne, at, Operand(zero_reg));
    cvt_s_w(dst, dst);
    srl(at, scratch, 31);
    sll(at, at, 31);
    mtc1(at, dst);
    bind(&done);
  }
}

void MacroAssembler::Floor_s_s(FPURegister dst, FPURegister src) {
  RoundFloat(dst, src, mode_floor,
             [](MacroAssembler* masm, FPURegister dst, FPURegister src) {
               masm->floor_w_s(dst, src);
             });
}

void MacroAssembler::Ceil_s_s(FPURegister dst, FPURegister src) {
  RoundFloat(dst, src, mode_ceil,
             [](MacroAssembler* masm, FPURegister dst, FPURegister src) {
               masm->ceil_w_s(dst, src);
             });
}

void MacroAssembler::Trunc_s_s(FPURegister dst, FPURegister src) {
  RoundFloat(dst, src, mode_trunc,
             [](MacroAssembler* masm, FPURegister dst, FPURegister src) {
               masm->trunc_w_s(dst, src);
             });
}

void MacroAssembler::Round_s_s(FPURegister dst, FPURegister src) {
  RoundFloat(dst, src, mode_round,
             [](MacroAssembler* masm, FPURegister dst, FPURegister src) {
               masm->round_w_s(dst, src);
             });
}

void MacroAssembler::LoadLane(MSASize sz, MSARegister dst, uint8_t laneidx,
                              MemOperand src) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  switch (sz) {
    case MSA_B:
      Lbu(scratch, src);
      insert_b(dst, laneidx, scratch);
      break;
    case MSA_H:
      Lhu(scratch, src);
      insert_h(dst, laneidx, scratch);
      break;
    case MSA_W:
      Lwu(scratch, src);
      insert_w(dst, laneidx, scratch);
      break;
    case MSA_D:
      Ld(scratch, src);
      insert_d(dst, laneidx, scratch);
      break;
    default:
      UNREACHABLE();
  }
}

void MacroAssembler::StoreLane(MSASize sz, MSARegister src, uint8_t laneidx,
                               MemOperand dst) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  switch (sz) {
    case MSA_B:
      copy_u_b(scratch, src, laneidx);
      Sb(scratch, dst);
      break;
    case MSA_H:
      copy_u_h(scratch, src, laneidx);
      Sh(scratch, dst);
      break;
    case MSA_W:
      if (laneidx == 0) {
        FPURegister src_reg = FPURegister::from_code(src.code());
        Swc1(src_reg, dst);
      } else {
        copy_u_w(scratch, src, laneidx);
        Sw(scratch, dst);
      }
      break;
    case MSA_D:
      if (laneidx == 0) {
        FPURegister src_reg = FPURegister::from_code(src.code());
        Sdc1(src_reg, dst);
      } else {
        copy_s_d(scratch, src, laneidx);
        Sd(scratch, dst);
      }
      break;
    default:
      UNREACHABLE();
  }
}

#define EXT_MUL_BINOP(type, ilv_instr, dotp_instr)            \
  case type:                                                  \
    xor_v(kSimd128RegZero, kSimd128RegZero, kSimd128RegZero); \
    ilv_instr(kSimd128ScratchReg, kSimd128RegZero, src1);     \
    ilv_instr(kSimd128RegZero, kSimd128RegZero, src2);        \
    dotp_instr(dst, kSimd128ScratchReg, kSimd128RegZero);     \
    break;

void MacroAssembler::ExtMulLow(MSADataType type, MSARegister dst,
                               MSARegister src1, MSARegister src2) {
  switch (type) {
    EXT_MUL_BINOP(MSAS8, ilvr_b, dotp_s_h)
    EXT_MUL_BINOP(MSAS16, ilvr_h, dotp_s_w)
    EXT_MUL_BINOP(MSAS32, ilvr_w, dotp_s_d)
    EXT_MUL_BINOP(MSAU8, ilvr_b, dotp_u_h)
    EXT_MUL_BINOP(MSAU16, ilvr_h, dotp_u_w)
    EXT_MUL_BINOP(MSAU32, ilvr_w, dotp_u_d)
    default:
      UNREACHABLE();
  }
}

void MacroAssembler::ExtMulHigh(MSADataType type, MSARegister dst,
                                MSARegister src1, MSARegister src2) {
  switch (type) {
    EXT_MUL_BINOP(MSAS8, ilvl_b, dotp_s_h)
    EXT_MUL_BINOP(MSAS16, ilvl_h, dotp_s_w)
    EXT_MUL_BINOP(MSAS32, ilvl_w, dotp_s_d)
    EXT_MUL_BINOP(MSAU8, ilvl_b, dotp_u_h)
    EXT_MUL_BINOP(MSAU16, ilvl_h, dotp_u_w)
    EXT_MUL_BINOP(MSAU32, ilvl_w, dotp_u_d)
    default:
      UNREACHABLE();
  }
}
#undef EXT_MUL_BINOP

void MacroAssembler::LoadSplat(MSASize sz, MSARegister dst, MemOperand src) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  switch (sz) {
    case MSA_B:
      Lb(scratch, src);
      fill_b(dst, scratch);
      break;
    case MSA_H:
      Lh(scratch, src);
      fill_h(dst, scratch);
      break;
    case MSA_W:
      Lw(scratch, src);
      fill_w(dst, scratch);
      break;
    case MSA_D:
      Ld(scratch, src);
      fill_d(dst, scratch);
      break;
    default:
      UNREACHABLE();
  }
}

void MacroAssembler::ExtAddPairwise(MSADataType type, MSARegister dst,
                                    MSARegister src) {
  switch (type) {
    case MSAS8:
      hadd_s_h(dst, src, src);
      break;
    case MSAU8:
      hadd_u_h(dst, src, src);
      break;
    case MSAS16:
      hadd_s_w(dst, src, src);
      break;
    case MSAU16:
      hadd_u_w(dst, src, src);
      break;
    default:
      UNREACHABLE();
  }
}

void MacroAssembler::MSARoundW(MSARegister dst, MSARegister src,
                               FPURoundingMode mode) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register scratch = t8;
  Register scratch2 = at;
  cfcmsa(scratch, MSACSR);
  if (mode == kRoundToNearest) {
    scratch2 = zero_reg;
  } else {
    li(scratch2, Operand(mode));
  }
  ctcmsa(MSACSR, scratch2);
  frint_w(dst, src);
  ctcmsa(MSACSR, scratch);
}

void MacroAssembler::MSARoundD(MSARegister dst, MSARegister src,
                               FPURoundingMode mode) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register scratch = t8;
  Register scratch2 = at;
  cfcmsa(scratch, MSACSR);
  if (mode == kRoundToNearest) {
    scratch2 = zero_reg;
  } else {
    li(scratch2, Operand(mode));
  }
  ctcmsa(MSACSR, scratch2);
  frint_d(dst, src);
  ctcmsa(MSACSR, scratch);
}

void MacroAssembler::Madd_s(FPURegister fd, FPURegister fr, FPURegister fs,
                            FPURegister ft, FPURegister scratch) {
  DCHECK(fr != scratch && fs != scratch && ft != scratch);
  mul_s(scratch, fs, ft);
  add_s(fd, fr, scratch);
}

void MacroAssembler::Madd_d(FPURegister fd, FPURegister fr, FPURegister fs,
                            FPURegister ft, FPURegister scratch) {
  DCHECK(fr != scratch && fs != scratch && ft != scratch);
  mul_d(scratch, fs, ft);
  add_d(fd, fr, scratch);
}

void MacroAssembler::Msub_s(FPURegister fd, FPURegister fr, FPURegister fs,
                            FPURegister ft, FPURegister scratch) {
  DCHECK(fr != scratch && fs != scratch && ft != scratch);
  mul_s(scratch, fs, ft);
  sub_s(fd, scratch, fr);
}

void MacroAssembler::Msub_d(FPURegister fd, FPURegister fr, FPURegister fs,
                            FPURegister ft, FPURegister scratch) {
  DCHECK(fr != scratch && fs != scratch && ft != scratch);
  mul_d(scratch, fs, ft);
  sub_d(fd, scratch, fr);
}

void MacroAssembler::CompareF(SecondaryField sizeField, FPUCondition cc,
                              FPURegister cmp1, FPURegister cmp2) {
  if (kArchVariant == kMips64r6) {
    sizeField = sizeField == D ? L : W;
    DCHECK(cmp1 != kDoubleCompareReg && cmp2 != kDoubleCompareReg);
    cmp(cc, sizeField, kDoubleCompareReg, cmp1, cmp2);
  } else {
    c(cc, sizeField, cmp1, cmp2);
  }
}

void MacroAssembler::CompareIsNanF(SecondaryField sizeField, FPURegister cmp1,
                                   FPURegister cmp2) {
  CompareF(sizeField, UN, cmp1, cmp2);
}

void MacroAssembler::BranchTrueShortF(Label* target, BranchDelaySlot bd) {
  if (kArchVariant == kMips64r6) {
    bc1nez(target, kDoubleCompareReg);
  } else {
    bc1t(target);
  }
  if (bd == PROTECT) {
    nop();
  }
}

void MacroAssembler::BranchFalseShortF(Label* target, BranchDelaySlot bd) {
  if (kArchVariant == kMips64r6) {
    bc1eqz(target, kDoubleCompareReg);
  } else {
    bc1f(target);
  }
  if (bd == PROTECT) {
    nop();
  }
}

void MacroAssembler::BranchTrueF(Label* target, BranchDelaySlot bd) {
  bool long_branch =
      target->is_bound() ? !is_near(target) : is_trampoline_emitted();
  if (long_branch) {
    Label skip;
    BranchFalseShortF(&skip);
    BranchLong(target, bd);
    bind(&skip);
  } else {
    BranchTrueShortF(target, bd);
  }
}

void MacroAssembler::BranchFalseF(Label* target, BranchDelaySlot bd) {
  bool long_branch =
      target->is_bound() ? !is_near(target) : is_trampoline_emitted();
  if (long_branch) {
    Label skip;
    BranchTrueShortF(&skip);
    BranchLong(target, bd);
    bind(&skip);
  } else {
    BranchFalseShortF(target, bd);
  }
}

void MacroAssembler::BranchMSA(Label* target, MSABranchDF df,
                               MSABranchCondition cond, MSARegister wt,
                               BranchDelaySlot bd) {
  {
    BlockTrampolinePoolScope block_trampoline_pool(this);

    if (target) {
      bool long_branch =
          target->is_bound() ? !is_near(target) : is_trampoline_emitted();
      if (long_branch) {
        Label skip;
        MSABranchCondition neg_cond = NegateMSABranchCondition(cond);
        BranchShortMSA(df, &skip, neg_cond, wt, bd);
        BranchLong(target, bd);
        bind(&skip);
      } else {
        BranchShortMSA(df, target, cond, wt, bd);
      }
    }
  }
}

void MacroAssembler::BranchShortMSA(MSABranchDF df, Label* target,
                                    MSABranchCondition cond, MSARegister wt,
                                    BranchDelaySlot bd) {
  if (IsEnabled(MIPS_SIMD)) {
    BlockTrampolinePoolScope block_trampoline_pool(this);
    if (target) {
      switch (cond) {
        case all_not_zero:
          switch (df) {
            case MSA_BRANCH_D:
              bnz_d(wt, target);
              break;
            case MSA_BRANCH_W:
              bnz_w(wt, target);
              break;
            case MSA_BRANCH_H:
              bnz_h(wt, target);
              break;
            case MSA_BRANCH_B:
            default:
              bnz_b(wt, target);
          }
          break;
        case one_elem_not_zero:
          bnz_v(wt, target);
          break;
        case one_elem_zero:
          switch (df) {
            case MSA_BRANCH_D:
              bz_d(wt, target);
              break;
            case MSA_BRANCH_W:
              bz_w(wt, target);
              break;
            case MSA_BRANCH_H:
              bz_h(wt, target);
              break;
            case MSA_BRANCH_B:
            default:
              bz_b(wt, target);
          }
          break;
        case all_zero:
          bz_v(wt, target);
          break;
        default:
          UNREACHABLE();
      }
    }
  } else {
    UNREACHABLE();
  }
  if (bd == PROTECT) {
    nop();
  }
}

void MacroAssembler::FmoveLow(FPURegister dst, Register src_low) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  DCHECK(src_low != scratch);
  mfhc1(scratch, dst);
  mtc1(src_low, dst);
  mthc1(scratch, dst);
}

void MacroAssembler::Move(FPURegister dst, uint32_t src) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  li(scratch, Operand(static_cast<int32_t>(src)));
  mtc1(scratch, dst);
}

void MacroAssembler::Move(FPURegister dst, uint64_t src) {
  // Handle special values first.
  if (src == base::bit_cast<uint64_t>(0.0) && has_double_zero_reg_set_) {
    mov_d(dst, kDoubleRegZero);
  } else if (src == base::bit_cast<uint64_t>(-0.0) &&
             has_double_zero_reg_set_) {
    Neg_d(dst, kDoubleRegZero);
  } else {
    uint32_t lo = src & 0xFFFFFFFF;
    uint32_t hi = src >> 32;
    // Move the low part of the double into the lower of the corresponding FPU
    // register of FPU register pair.
    if (lo != 0) {
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      li(scratch, Operand(lo));
      mtc1(scratch, dst);
    } else {
      mtc1(zero_reg, dst);
    }
    // Move the high part of the double into the higher of the corresponding FPU
    // register of FPU register pair.
    if (hi != 0) {
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      li(scratch, Operand(hi));
      mthc1(scratch, dst);
    } else {
      mthc1(zero_reg, dst);
    }
    if (dst == kDoubleRegZero) has_double_zero_reg_set_ = true;
  }
}

void MacroAssembler::Movz(Register rd, Register rs, Register rt) {
  if (kArchVariant == kMips64r6) {
    Label done;
    Branch(&done, ne, rt, Operand(zero_reg));
    mov(rd, rs);
    bind(&done);
  } else {
    movz(rd, rs, rt);
  }
}

void MacroAssembler::Movn(Register rd, Register rs, Register rt) {
  if (kArchVariant == kMips64r6) {
    Label done;
    Branch(&done, eq, rt, Operand(zero_reg));
    mov(rd, rs);
    bind(&done);
  } else {
    movn(rd, rs, rt);
  }
}

void MacroAssembler::LoadZeroIfConditionNotZero(Register dest,
                                                Register condition) {
  if (kArchVariant == kMips64r6) {
    seleqz(dest, dest, condition);
  } else {
    Movn(dest, zero_reg, condition);
  }
}

void MacroAssembler::LoadZeroIfConditionZero(Register dest,
                                             Register condition) {
  if (kArchVariant == kMips64r6) {
    selnez(dest, dest, condition);
  } else {
    Movz(dest, zero_reg, condition);
  }
}

void MacroAssembler::LoadZeroIfFPUCondition(Register dest) {
  if (kArchVariant == kMips64r6) {
    dmfc1(kScratchReg, kDoubleCompareReg);
    LoadZeroIfConditionNotZero(dest, kScratchReg);
  } else {
    Movt(dest, zero_reg);
  }
}

void MacroAssembler::LoadZeroIfNotFPUCondition(Register dest) {
  if (kArchVariant == kMips64r6) {
    dmfc1(kScratchReg, kDoubleCompareReg);
    LoadZeroIfConditionZero(dest, kScratchReg);
  } else {
    Movf(dest, zero_reg);
  }
}

void MacroAssembler::Movt(Register rd, Register rs, uint16_t cc) {
  movt(rd, rs, cc);
}

void MacroAssembler::Movf(Register rd, Register rs, uint16_t cc) {
  movf(rd, rs, cc);
}

void MacroAssembler::Clz(Register rd, Register rs) { clz(rd, rs); }

void MacroAssembler::Dclz(Register rd, Register rs) { dclz(rd, rs); }

void MacroAssembler::Ctz(Register rd, Register rs) {
  if (kArchVariant == kMips64r6) {
    // We don't have an instruction to count the number of trailing zeroes.
    // Start by flipping the bits end-for-end so we can count the number of
    // leading zeroes instead.
    rotr(rd, rs, 16);
    wsbh(rd, rd);
    bitswap(rd, rd);
    Clz(rd, rd);
  } else {
    // Convert trailing zeroes to trailing ones, and bits to their left
    // to zeroes.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Daddu(scratch, rs, -1);
    Xor(rd, scratch, rs);
    And(rd, rd, scratch);
    // Count number of leading zeroes.
    Clz(rd, rd);
    // Subtract number of leading zeroes from 32 to get number of trailing
    // ones. Remember that the trailing ones were formerly trailing zeroes.
    li(scratch, 32);
    Subu(rd, scratch, rd);
  }
}

void MacroAssembler::Dctz(Register rd, Register rs) {
  if (kArchVariant == kMips64r6) {
    // We don't have an instruction to count the number of trailing zeroes.
    // Start by flipping the bits end-for-end so we can count the number of
    // leading zeroes instead.
    dsbh(rd, rs);
    dshd(rd, rd);
    dbitswap(rd, rd);
    dclz(rd, rd);
  } else {
    // Convert trailing zeroes to trailing ones, and bits to their left
    // to zeroes.
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Daddu(scratch, rs, -1);
    Xor(rd, scratch, rs);
    And(rd, rd, scratch);
    // Count number of leading zeroes.
    dclz(rd, rd);
    // Subtract number of leading zeroes from 64 to get number of trailing
    // ones. Remember that the trailing ones were formerly trailing zeroes.
    li(scratch, 64);
    Dsubu(rd, scratch, rd);
  }
}

void MacroAssembler::Popcnt(Register rd, Register rs) {
  ASM_CODE_COMMENT(this);
  // https://graphics.stanford.edu/~seander/bithacks.html#CountBitsSetParallel
  //
  // A generalization of the best bit counting method to integers of
  // bit-widths up to 128 (parameterized by type T) is this:
  //
  // v = v - ((v >> 1) & (T)~(T)0/3);                           // temp
  // v = (v & (T)~(T)0/15*3) + ((v >> 2) & (T)~(T)0/15*3);      // temp
  // v = (v + (v >> 4)) & (T)~(T)0/255*15;                      // temp
  // c = (T)(v * ((T)~(T)0/255)) >> (sizeof(T) - 1) * BITS_PER_BYTE; //count
  //
  // For comparison, for 32-bit quantities, this algorithm can be executed
  // using 20 MIPS instructions (the calls to LoadConst32() generate two
  // machine instructions each for the values being used in this algorithm).
  // A(n unrolled) loop-based algorithm requires 25 instructions.
  //
  // For a 64-bit operand this can be performed in 24 instructions compared
  // to a(n unrolled) loop based algorithm which requires 38 instructions.
  //
  // There are algorithms which are faster in the cases where very few
  // bits are set but the algorithm here attempts to minimize the total
  // number of instructions executed even when a large number of bits
  // are set.
  uint32_t B0 = 0x55555555;     // (T)~(T)0/3
  uint32_t B1 = 0x33333333;     // (T)~(T)0/15*3
  uint32_t B2 = 0x0F0F0F0F;     // (T)~(T)0/255*15
  uint32_t value = 0x01010101;  // (T)~(T)0/255
  uint32_t shift = 24;          // (sizeof(T) - 1) * BITS_PER_BYTE

  UseScratchRegisterScope temps(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register scratch = temps.Acquire();
  Register scratch2 = t8;
  srl(scratch, rs, 1);
  li(scratch2, B0);
  And(scratch, scratch, scratch2);
  Subu(scratch, rs, scratch);
  li(scratch2, B1);
  And(rd, scratch, scratch2);
  srl(scratch, scratch, 2);
  And(scratch, scratch, scratch2);
  Addu(scratch, rd, scratch);
  srl(rd, scratch, 4);
  Addu(rd, rd, scratch);
  li(scratch2, B2);
  And(rd, rd, scratch2);
  li(scratch, value);
  Mul(rd, rd, scratch);
  srl(rd, rd, shift);
}

void MacroAssembler::Dpopcnt(Register rd, Register rs) {
  ASM_CODE_COMMENT(this);
  uint64_t B0 = 0x5555555555555555l;     // (T)~(T)0/3
  uint64_t B1 = 0x3333333333333333l;     // (T)~(T)0/15*3
  uint64_t B2 = 0x0F0F0F0F0F0F0F0Fl;     // (T)~(T)0/255*15
  uint64_t value = 0x0101010101010101l;  // (T)~(T)0/255
  uint64_t shift = 24;                   // (sizeof(T) - 1) * BITS_PER_BYTE

  UseScratchRegisterScope temps(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register scratch = temps.Acquire();
  Register scratch2 = t8;
  dsrl(scratch, rs, 1);
  li(scratch2, B0);
  And(scratch, scratch, scratch2);
  Dsubu(scratch, rs, scratch);
  li(scratch2, B1);
  And(rd, scratch, scratch2);
  dsrl(scratch, scratch, 2);
  And(scratch, scratch, scratch2);
  Daddu(scratch, rd, scratch);
  dsrl(rd, scratch, 4);
  Daddu(rd, rd, scratch);
  li(scratch2, B2);
  And(rd, rd, scratch2);
  li(scratch, value);
  Dmul(rd, rd, scratch);
  dsrl32(rd, rd, shift);
}

void MacroAssembler::TryInlineTruncateDoubleToI(Register result,
                                                DoubleRegister double_input,
                                                Label* done) {
  DoubleRegister single_scratch = kScratchDoubleReg.low();
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register scratch = t9;

  // Try a conversion to a signed integer.
  trunc_w_d(single_scratch, double_input);
  mfc1(result, single_scratch);
  // Retrieve the FCSR.
  cfc1(scratch, FCSR);
  // Check for overflow and NaNs.
  And(scratch, scratch,
      kFCSROverflowCauseMask | kFCSRUnderflowCauseMask |
          kFCSRInvalidOpCauseMask);
  // If we had no exceptions we are done.
  Branch(done, eq, scratch, Operand(zero_reg));
}

void MacroAssembler::TruncateDoubleToI(Isolate* isolate, Zone* zone,
                                       Register result,
                                       DoubleRegister double_input,
                                       StubCallMode stub_mode) {
  Label done;

  TryInlineTruncateDoubleToI(result, double_input, &done);

  // If we fell through then inline version didn't succeed - call stub instead.
  push(ra);
  Dsubu(sp, sp, Operand(kDoubleSize));  // Put input on stack.
  Sdc1(double_input, MemOperand(sp, 0));

#if V8_ENABLE_WEBASSEMBLY
  if (stub_mode == StubCallMode::kCallWasmRuntimeStub) {
    Call(static_cast<Address>(Builtin::kDoubleToI), RelocInfo::WASM_STUB_CALL);
#else
  // For balance.
  if (false) {
#endif  // V8_ENABLE_WEBASSEMBLY
  } else {
    CallBuiltin(Builtin::kDoubleToI);
  }
  Ld(result, MemOperand(sp, 0));

  Daddu(sp, sp, Operand(kDoubleSize));
  pop(ra);

  bind(&done);
}

void MacroAssembler::CompareWord(Condition cond, Register dst, Register lhs,
                                 const Operand& rhs) {
  switch (cond) {
    case eq:
    case ne: {
      if (rhs.IsImmediate()) {
        if (rhs.immediate() == 0) {
          if (cond == eq) {
            Sltu(dst, lhs, 1);
          } else {
            Sltu(dst, zero_reg, lhs);
          }
        } else if (is_int16(-rhs.immediate())) {
          Daddu(dst, lhs, Operand(-rhs.immediate()));
          if (cond == eq) {
            Sltu(dst, dst, 1);
          } else {
            Sltu(dst, zero_reg, dst);
          }
        } else {
          Xor(dst, lhs, rhs);
          if (cond == eq) {
            Sltu(dst, dst, 1);
          } else {
            Sltu(dst, zero_reg, dst);
          }
        }
      } else {
        Xor(dst, lhs, rhs);
        if (cond == eq) {
          Sltu(dst, dst, 1);
        } else {
          Sltu(dst, zero_reg, dst);
        }
      }
      break;
    }
    case lt:
      Slt(dst, lhs, rhs);
      break;
    case gt:
      Sgt(dst, lhs, rhs);
      break;
    case le:
      Sle(dst, lhs, rhs);
      break;
    case ge:
      Sge(dst, lhs, rhs);
      break;
    case lo:
      Sltu(dst, lhs, rhs);
      break;
    case hs:
      Sgeu(dst, lhs, rhs);
      break;
    case hi:
      Sgtu(dst, lhs, rhs);
      break;
    case ls:
      Sleu(dst, lhs, rhs);
      break;
    default:
      UNREACHABLE();
  }
}

// Emulated condtional branches do not emit a nop in the branch delay slot.
//
// BRANCH_ARGS_CHECK checks that conditional jump arguments are correct.
#define BRANCH_ARGS_CHECK(cond, rs, rt)                                  \
  DCHECK((cond == cc_always && rs == zero_reg && rt.rm() == zero_reg) || \
         (cond != cc_always && (rs != zero_reg || rt.rm() != zero_reg)))

void MacroAssembler::Branch(int32_t offset, BranchDelaySlot bdslot) {
  DCHECK_EQ(kArchVariant, kMips64r6 ? is_int26(offset) : is_int16(offset));
  BranchShort(offset, bdslot);
}

void MacroAssembler::Branch(int32_t offset, Condition cond, Register rs,
                            const Operand& rt, BranchDelaySlot bdslot) {
  bool is_near = BranchShortCheck(offset, nullptr, cond, rs, rt, bdslot);
  DCHECK(is_near);
  USE(is_near);
}

void MacroAssembler::Branch(Label* L, BranchDelaySlot bdslot) {
  if (L->is_bound()) {
    if (is_near_branch(L)) {
      BranchShort(L, bdslot);
    } else {
      BranchLong(L, bdslot);
    }
  } else {
    if (is_trampoline_emitted()) {
      BranchLong(L, bdslot);
    } else {
      BranchShort(L, bdslot);
    }
  }
}

void MacroAssembler::Branch(Label* L, Condition cond, Register rs,
                            const Operand& rt, BranchDelaySlot bdslot) {
  if (L->is_bound()) {
    if (!BranchShortCheck(0, L, cond, rs, rt, bdslot)) {
      if (cond != cc_always) {
        Label skip;
        Condition neg_cond = NegateCondition(cond);
        BranchShort(&skip, neg_cond, rs, rt);
        BranchLong(L, bdslot);
        bind(&skip);
      } else {
        BranchLong(L, bdslot);
      }
    }
  } else {
    if (is_trampoline_emitted()) {
      if (cond != cc_always) {
        Label skip;
        Condition neg_cond = NegateCondition(cond);
        BranchShort(&skip, neg_cond, rs, rt);
        BranchLong(L, bdslot);
        bind(&skip);
      } else {
        BranchLong(L, bdslot);
      }
    } else {
      BranchShort(L, cond, rs, rt, bdslot);
    }
  }
}

void MacroAssembler::Branch(Label* L, Condition cond, Register rs,
                            RootIndex index, BranchDelaySlot bdslot) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  LoadRoot(scratch, index);
  Branch(L, cond, rs, Operand(scratch), bdslot);
}

void MacroAssembler::BranchShortHelper(int16_t offset, Label* L,
                                       BranchDelaySlot bdslot) {
  DCHECK(L == nullptr || offset == 0);
  offset = GetOffset(offset, L, OffsetSize::kOffset16);
  b(offset);

  // Emit a nop in the branch delay slot if required.
  if (bdslot == PROTECT) nop();
}

void MacroAssembler::BranchShortHelperR6(int32_t offset, Label* L) {
  DCHECK(L == nullptr || offset == 0);
  offset = GetOffset(offset, L, OffsetSize::kOffset26);
  bc(offset);
}

void MacroAssembler::BranchShort(int32_t offset, BranchDelaySlot bdslot) {
  if (kArchVariant == kMips64r6 && bdslot == PROTECT) {
    DCHECK(is_int26(offset));
    BranchShortHelperR6(offset, nullptr);
  } else {
    DCHECK(is_int16(offset));
    BranchShortHelper(offset, nullptr, bdslot);
  }
}

void MacroAssembler::BranchShort(Label* L, BranchDelaySlot bdslot) {
  if (kArchVariant == kMips64r6 && bdslot == PROTECT) {
    BranchShortHelperR6(0, L);
  } else {
    BranchShortHelper(0, L, bdslot);
  }
}

int32_t MacroAssembler::GetOffset(int32_t offset, Label* L, OffsetSize bits) {
  if (L) {
    offset = branch_offset_helper(L, bits) >> 2;
  } else {
    DCHECK(is_intn(offset, bits));
  }
  return offset;
}

Register MacroAssembler::GetRtAsRegisterHelper(const Operand& rt,
                                               Register scratch) {
  Register r2 = no_reg;
  if (rt.is_reg()) {
    r2 = rt.rm();
  } else {
    r2 = scratch;
    li(r2, rt);
  }

  return r2;
}

bool MacroAssembler::CalculateOffset(Label* L, int32_t* offset,
                                     OffsetSize bits) {
  if (!is_near(L, bits)) return false;
  *offset = GetOffset(*offset, L, bits);
  return true;
}

bool MacroAssembler::CalculateOffset(Label* L, int32_t* offset, OffsetSize bits,
                                     Register* scratch, const Operand& rt) {
  if (!is_near(L, bits)) return false;
  *scratch = GetRtAsRegisterHelper(rt, *scratch);
  *offset = GetOffset(*offset, L, bits);
  return true;
}

bool MacroAssembler::BranchShortHelperR6(int32_t offset, Label* L,
                                         Condition cond, Register rs,
                                         const Operand& rt) {
  DCHECK(L == nullptr || offset == 0);
  UseScratchRegisterScope temps(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register scratch = temps.hasAvailable() ? temps.Acquire() : t8;

  // Be careful to always use shifted_branch_offset only just before the
  // branch instruction, as the location will be remember for patching the
  // target.
  {
    BlockTrampolinePoolScope block_trampoline_pool(this);
    switch (cond) {
      case cc_always:
        if (!CalculateOffset(L, &offset, OffsetSize::kOffset26)) return false;
        bc(offset);
        break;
      case eq:
        if (rt.is_reg() && rs.code() == rt.rm().code()) {
          // Pre R6 beq is used here to make the code patchable. Otherwise bc
          // should be used which has no condition field so is not patchable.
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset16, &scratch, rt))
            return false;
          beq(rs, scratch, offset);
          nop();
        } else if (IsZero(rt)) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset21)) return false;
          beqzc(rs, offset);
        } else {
          // We don't want any other register but scratch clobbered.
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset16, &scratch, rt))
            return false;
          beqc(rs, scratch, offset);
        }
        break;
      case ne:
        if (rt.is_reg() && rs.code() == rt.rm().code()) {
          // Pre R6 bne is used here to make the code patchable. Otherwise we
          // should not generate any instruction.
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset16, &scratch, rt))
            return false;
          bne(rs, scratch, offset);
          nop();
        } else if (IsZero(rt)) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset21)) return false;
          bnezc(rs, offset);
        } else {
          // We don't want any other register but scratch clobbered.
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset16, &scratch, rt))
            return false;
          bnec(rs, scratch, offset);
        }
        break;

      // Signed comparison.
      case greater:
        // rs > rt
        if (rt.is_reg() && rs.code() == rt.rm().code()) {
          break;  // No code needs to be emitted.
        } else if (rs == zero_reg) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset16, &scratch, rt))
            return false;
          bltzc(scratch, offset);
        } else if (IsZero(rt)) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset16)) return false;
          bgtzc(rs, offset);
        } else {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset16, &scratch, rt))
            return false;
          DCHECK(rs != scratch);
          bltc(scratch, rs, offset);
        }
        break;
      case greater_equal:
        // rs >= rt
        if (rt.is_reg() && rs.code() == rt.rm().code()) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset26)) return false;
          bc(offset);
        } else if (rs == zero_reg) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset16, &scratch, rt))
            return false;
          blezc(scratch, offset);
        } else if (IsZero(rt)) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset16)) return false;
          bgezc(rs, offset);
        } else {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset16, &scratch, rt))
            return false;
          DCHECK(rs != scratch);
          bgec(rs, scratch, offset);
        }
        break;
      case less:
        // rs < rt
        if (rt.is_reg() && rs.code() == rt.rm().code()) {
          break;  // No code needs to be emitted.
        } else if (rs == zero_reg) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset16, &scratch, rt))
            return false;
          bgtzc(scratch, offset);
        } else if (IsZero(rt)) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset16)) return false;
          bltzc(rs, offset);
        } else {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset16, &scratch, rt))
            return false;
          DCHECK(rs != scratch);
          bltc(rs, scratch, offset);
        }
        break;
      case less_equal:
        // rs <= rt
        if (rt.is_reg() && rs.code() == rt.rm().code()) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset26)) return false;
          bc(offset);
        } else if (rs == zero_reg) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset16, &scratch, rt))
            return false;
          bgezc(scratch, offset);
        } else if (IsZero(rt)) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset16)) return false;
          blezc(rs, offset);
        } else {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset16, &scratch, rt))
            return false;
          DCHECK(rs != scratch);
          bgec(scratch, rs, offset);
        }
        break;

      // Unsigned comparison.
      case Ugreater:
        // rs > rt
        if (rt.is_reg() && rs.code() == rt.rm().code()) {
          break;  // No code needs to be emitted.
        } else if (rs == zero_reg) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset21, &scratch, rt))
            return false;
          bnezc(scratch, offset);
        } else if (IsZero(rt)) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset21)) return false;
          bnezc(rs, offset);
        } else {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset16, &scratch, rt))
            return false;
          DCHECK(rs != scratch);
          bltuc(scratch, rs, offset);
        }
        break;
      case Ugreater_equal:
        // rs >= rt
        if (rt.is_reg() && rs.code() == rt.rm().code()) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset26)) return false;
          bc(offset);
        } else if (rs == zero_reg) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset21, &scratch, rt))
            return false;
          beqzc(scratch, offset);
        } else if (IsZero(rt)) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset26)) return false;
          bc(offset);
        } else {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset16, &scratch, rt))
            return false;
          DCHECK(rs != scratch);
          bgeuc(rs, scratch, offset);
        }
        break;
      case Uless:
        // rs < rt
        if (rt.is_reg() && rs.code() == rt.rm().code()) {
          break;  // No code needs to be emitted.
        } else if (rs == zero_reg) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset21, &scratch, rt))
            return false;
          bnezc(scratch, offset);
        } else if (IsZero(rt)) {
          break;  // No code needs to be emitted.
        } else {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset16, &scratch, rt))
            return false;
          DCHECK(rs != scratch);
          bltuc(rs, scratch, offset);
        }
        break;
      case Uless_equal:
        // rs <= rt
        if (rt.is_reg() && rs.code() == rt.rm().code()) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset26)) return false;
          bc(offset);
        } else if (rs == zero_reg) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset26, &scratch, rt))
            return false;
          bc(offset);
        } else if (IsZero(rt)) {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset21)) return false;
          beqzc(rs, offset);
        } else {
          if (!CalculateOffset(L, &offset, OffsetSize::kOffset16, &scratch, rt))
            return false;
          DCHECK(rs != scratch);
          bgeuc(scratch, rs, offset);
        }
        break;
      default:
        UNREACHABLE();
    }
  }
  CheckTrampolinePoolQuick(1);
  return true;
}

bool MacroAssembler::BranchShortHelper(int16_t offset, Label* L, Condition cond,
                                       Register rs, const Operand& rt,
                                       BranchDelaySlot bdslot) {
  DCHECK(L == nullptr || offset == 0);
  if (!is_near(L, OffsetSize::kOffset16)) return false;

  UseScratchRegisterScope temps(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register scratch = temps.hasAvailable() ? temps.Acquire() : t8;
  int32_t offset32;

  // Be careful to always use shifted_branch_offset only just before the
  // branch instruction, as the location will be remember for patching the
  // target.
  {
    BlockTrampolinePoolScope block_trampoline_pool(this);
    switch (cond) {
      case cc_always:
        offset32 = GetOffset(offset, L, OffsetSize::kOffset16);
        b(offset32);
        break;
      case eq:
        if (IsZero(rt)) {
          offset32 = GetOffset(offset, L, OffsetSize::kOffset16);
          beq(rs, zero_reg, offset32);
        } else {
          // We don't want any other register but scratch clobbered.
          scratch = GetRtAsRegisterHelper(rt, scratch);
          offset32 = GetOffset(offset, L, OffsetSize::kOffset16);
          beq(rs, scratch, offset32);
        }
        break;
      case ne:
        if (IsZero(rt)) {
          offset32 = GetOffset(offset, L, OffsetSize::kOffset16);
          bne(rs, zero_reg, offset32);
        } else {
          // We don't want any other register but scratch clobbered.
          scratch = GetRtAsRegisterHelper(rt, scratch);
          offset32 = GetOffset(offset, L, OffsetSize::kOffset16);
          bne(rs, scratch, offset32);
        }
        break;

      // Signed comparison.
      case greater:
        if (IsZero(rt)) {
          offset32 = GetOffset(offset, L, OffsetSize::kOffset16);
          bgtz(rs, offset32);
        } else {
          Slt(scratch, GetRtAsRegisterHelper(rt, scratch), rs);
          offset32 = GetOffset(offset, L, OffsetSize::kOffset16);
          bne(scratch, zero_reg, offset32);
        }
        break;
      case greater_equal:
        if (IsZero(rt)) {
          offset32 = GetOffset(offset, L, OffsetSize::kOffset16);
          bgez(rs, offset32);
        } else {
          Slt(scratch, rs, rt);
          offset32 = GetOffset(offset, L, OffsetSize::kOffset16);
          beq(scratch, zero_reg, offset32);
        }
        break;
      case less:
        if (IsZero(rt)) {
          offset32 = GetOffset(offset, L, OffsetSize::kOffset16);
          bltz(rs, offset32);
        } else {
          Slt(scratch, rs, rt);
          offset32 = GetOffset(offset, L, OffsetSize::kOffset16);
          bne(scratch, zero_reg, offset32);
        }
        break;
      case less_equal:
        if (IsZero(rt)) {
          offset32 = GetOffset(offset, L, OffsetSize::kOffset16);
          blez(rs, offset32);
        } else {
          Slt(scratch, GetRtAsRegisterHelper(rt, scratch), rs);
          offset32 = GetOffset(offset, L, OffsetSize::kOffset16);
          beq(scratch, zero_reg, offset32);
        }
        break;

      // Unsigned comparison.
      case Ugreater:
        if (IsZero(rt)) {
          offset32 = GetOffset(offset, L, OffsetSize::kOffset16);
          bne(rs, zero_reg, offset32);
        } else {
          Sltu(scratch, GetRtAsRegisterHelper(rt, scratch), rs);
          offset32 = GetOffset(offset, L, OffsetSize::kOffset16);
          bne(scratch, zero_reg, offset32);
        }
        break;
      case Ugreater_equal:
        if (IsZero(rt)) {
          offset32 = GetOffset(offset, L, OffsetSize::kOffset16);
          b(offset32);
        } else {
          Sltu(scratch, rs, rt);
          offset32 = GetOffset(offset, L, OffsetSize::kOffset16);
          beq(scratch, zero_reg, offset32);
        }
        break;
      case Uless:
        if (IsZero(rt)) {
          return true;  // No code needs to be emitted.
        } else {
          Sltu(scratch, rs, rt);
          offset32 = GetOffset(offset, L, OffsetSize::kOffset16);
          bne(scratch, zero_reg, offset32);
        }
        break;
      case Uless_equal:
        if (IsZero(rt)) {
          offset32 = GetOffset(offset, L, OffsetSize::kOffset16);
          beq(rs, zero_reg, offset32);
        } else {
          Sltu(scratch, GetRtAsRegisterHelper(rt, scratch), rs);
          offset32 = GetOffset(offset, L, OffsetSize::kOffset16);
          beq(scratch, zero_reg, offset32);
        }
        break;
      default:
        UNREACHABLE();
    }
  }

  // Emit a nop in the branch delay slot if required.
  if (bdslot == PROTECT) nop();

  return true;
}

bool MacroAssembler::BranchShortCheck(int32_t offset, Label* L, Condition cond,
                                      Register rs, const Operand& rt,
                                      BranchDelaySlot bdslot) {
  BRANCH_ARGS_CHECK(cond, rs, rt);

  if (!L) {
    if (kArchVariant == kMips64r6 && bdslot == PROTECT) {
      DCHECK(is_int26(offset));
      return BranchShortHelperR6(offset, nullptr, cond, rs, rt);
    } else {
      DCHECK(is_int16(offset));
      return BranchShortHelper(offset, nullptr, cond, rs, rt, bdslot);
    }
  } else {
    DCHECK_EQ(offset, 0);
    if (kArchVariant == kMips64r6 && bdslot == PROTECT) {
      return BranchShortHelperR6(0, L, cond, rs, rt);
    } else {
      return BranchShortHelper(0, L, cond, rs, rt, bdslot);
    }
  }
}

void MacroAssembler::BranchShort(int32_t offset, Condition cond, Register rs,
                                 const Operand& rt, BranchDelaySlot bdslot) {
  BranchShortCheck(offset, nullptr, cond, rs, rt, bdslot);
}

void MacroAssembler::BranchShort(Label* L, Condition cond, Register rs,
                                 const Operand& rt, BranchDelaySlot bdslot) {
  BranchShortCheck(0, L, cond, rs, rt, bdslot);
}

void MacroAssembler::BranchAndLink(int32_t offset, BranchDelaySlot bdslot) {
  BranchAndLinkShort(offset, bdslot);
}

void MacroAssembler::BranchAndLink(int32_t offset, Condition cond, Register rs,
                                   const Operand& rt, BranchDelaySlot bdslot) {
  bool is_near = BranchAndLinkShortCheck(offset, nullptr, cond, rs, rt, bdslot);
  DCHECK(is_near);
  USE(is_near);
}

void MacroAssembler::BranchAndLink(Label* L, BranchDelaySlot bdslot) {
  if (L->is_bound()) {
    if (is_near_branch(L)) {
      BranchAndLinkShort(L, bdslot);
    } else {
      BranchAndLinkLong(L, bdslot);
    }
  } else {
    if (is_trampoline_emitted()) {
      BranchAndLinkLong(L, bdslot);
    } else {
      BranchAndLinkShort(L, bdslot);
    }
  }
}

void MacroAssembler::BranchAndLink(Label* L, Condition cond, Register rs,
                                   const Operand& rt, BranchDelaySlot bdslot) {
  if (L->is_bound()) {
    if (!BranchAndLinkShortCheck(0, L, cond, rs, rt, bdslot)) {
      Label skip;
      Condition neg_cond = NegateCondition(cond);
      BranchShort(&skip, neg_cond, rs, rt);
      BranchAndLinkLong(L, bdslot);
      bind(&skip);
    }
  } else {
    if (is_trampoline_emitted()) {
      Label skip;
      Condition neg_cond = NegateCondition(cond);
      BranchShort(&skip, neg_cond, rs, rt);
      BranchAndLinkLong(L, bdslot);
      bind(&skip);
    } else {
      BranchAndLinkShortCheck(0, L, cond, rs, rt, bdslot);
    }
  }
}

void MacroAssembler::BranchAndLinkShortHelper(int16_t offset, Label* L,
                                              BranchDelaySlot bdslot) {
  DCHECK(L == nullptr || offset == 0);
  offset = GetOffset(offset, L, OffsetSize::kOffset16);
  bal(offset);

  // Emit a nop in the branch delay slot if required.
  if (bdslot == PROTECT) nop();
}

void MacroAssembler::BranchAndLinkShortHelperR6(int32_t offset, Label* L) {
  DCHECK(L == nullptr || offset == 0);
  offset = GetOffset(offset, L, OffsetSize::kOffset26);
  balc(offset);
}

void MacroAssembler::BranchAndLinkShort(int32_t offset,
                                        BranchDelaySlot bdslot) {
  if (kArchVariant == kMips64r6 && bdslot == PROTECT) {
    DCHECK(is_int26(offset));
    BranchAndLinkShortHelperR6(offset, nullptr);
  } else {
    DCHECK(is_int16(offset));
    BranchAndLinkShortHelper(offset, nullptr, bdslot);
  }
}

void MacroAssembler::BranchAndLinkShort(Label* L, BranchDelaySlot bdslot) {
  if (kArchVariant == kMips64r6 && bdslot == PROTECT) {
    BranchAndLinkShortHelperR6(0, L);
  } else {
    BranchAndLinkShortHelper(0, L, bdslot);
  }
}

bool MacroAssembler::BranchAndLinkShortHelperR6(int32_t offset, Label* L,
                                                Condition cond, Register rs,
                                                const Operand& rt) {
  DCHECK(L == nullptr || offset == 0);
  UseScratchRegisterScope temps(this);
  Register scratch = temps.hasAvailable() ? temps.Acquire() : t8;
  OffsetSize bits = OffsetSize::kOffset16;

  BlockTrampolinePoolScope block_trampoline_pool(this);
  DCHECK((cond == cc_always && is_int26(offset)) || is_int16(offset));
  switch (cond) {
    case cc_always:
      if (!CalculateOffset(L, &offset, OffsetSize::kOffset26)) return false;
      balc(offset);
      break;
    case eq:
      if (!is_near(L, bits)) return false;
      Subu(scratch, rs, rt);
      offset = GetOffset(offset, L, bits);
      beqzalc(scratch, offset);
      break;
    case ne:
      if (!is_near(L, bits)) return false;
      Subu(scratch, rs, rt);
      offset = GetOffset(offset, L, bits);
      bnezalc(scratch, offset);
      break;

    // Signed comparison.
    case greater:
      // rs > rt
      if (rs.code() == rt.rm().code()) {
        break;  // No code needs to be emitted.
      } else if (rs == zero_reg) {
        if (!CalculateOffset(L, &offset, OffsetSize::kOffset16, &scratch, rt))
          return false;
        bltzalc(scratch, offset);
      } else if (IsZero(rt)) {
        if (!CalculateOffset(L, &offset, OffsetSize::kOffset16)) return false;
        bgtzalc(rs, offset);
      } else {
        if (!is_near(L, bits)) return false;
        Slt(scratch, GetRtAsRegisterHelper(rt, scratch), rs);
        offset = GetOffset(offset, L, bits);
        bnezalc(scratch, offset);
      }
      break;
    case greater_equal:
      // rs >= rt
      if (rs.code() == rt.rm().code()) {
        if (!CalculateOffset(L, &offset, OffsetSize::kOffset26)) return false;
        balc(offset);
      } else if (rs == zero_reg) {
        if (!CalculateOffset(L, &offset, OffsetSize::kOffset16, &scratch, rt))
          return false;
        blezalc(scratch, offset);
      } else if (IsZero(rt)) {
        if (!CalculateOffset(L, &offset, OffsetSize::kOffset16)) return false;
        bgezalc(rs, offset);
      } else {
        if (!is_near(L, bits)) return false;
        Slt(scratch, rs, rt);
        offset = GetOffset(offset, L, bits);
        beqzalc(scratch, offset);
      }
      break;
    case less:
      // rs < rt
      if (rs.code() == rt.rm().code()) {
        break;  // No code needs to be emitted.
      } else if (rs == zero_reg) {
        if (!CalculateOffset(L, &offset, OffsetSize::kOffset16, &scratch, rt))
          return false;
        bgtzalc(scratch, offset);
      } else if (IsZero(rt)) {
        if (!CalculateOffset(L, &offset, OffsetSize::kOffset16)) return false;
        bltzalc(rs, offset);
      } else {
        if (!is_near(L, bits)) return false;
        Slt(scratch, rs, rt);
        offset = GetOffset(offset, L, bits);
        bnezalc(scratch, offset);
      }
      break;
    case less_equal:
      // rs <= r2
      if (rs.code() == rt.rm().code()) {
        if (!CalculateOffset(L, &offset, OffsetSize::kOffset26)) return false;
        balc(offset);
      } else if (rs == zero_reg) {
        if (!CalculateOffset(L, &offset, OffsetSize::kOffset16, &scratch, rt))
          return false;
        bgezalc(scratch, offset);
      } else if (IsZero(rt)) {
        if (!CalculateOffset(L, &offset, OffsetSize::kOffset16)) return false;
        blezalc(rs, offset);
      } else {
        if (!is_near(L, bits)) return false;
        Slt(scratch, GetRtAsRegisterHelper(rt, scratch), rs);
        offset = GetOffset(offset, L, bits);
        beqzalc(scratch, offset);
      }
      break;

    // Unsigned comparison.
    case Ugreater:
      // rs > r2
      if (!is_near(L, bits)) return false;
      Sltu(scratch, GetRtAsRegisterHelper(rt, scratch), rs);
      offset = GetOffset(offset, L, bits);
      bnezalc(scratch, offset);
      break;
    case Ugreater_equal:
      // rs >= r2
      if (!is_near(L, bits)) return false;
      Sltu(scratch, rs, rt);
      offset = GetOffset(offset, L, bits);
      beqzalc(scratch, offset);
      break;
    case Uless:
      // rs < r2
      if (!is_near(L, bits)) return false;
      Sltu(scratch, rs, rt);
      offset = GetOffset(offset, L, bits);
      bnezalc(scratch, offset);
      break;
    case Uless_equal:
      // rs <= r2
      if (!is_near(L, bits)) return false;
      Sltu(scratch, GetRtAsRegisterHelper(rt, scratch), rs);
      offset = GetOffset(offset, L, bits);
      beqzalc(scratch, offset);
      break;
    default:
      UNREACHABLE();
  }
  return true;
}

// Pre r6 we need to use a bgezal or bltzal, but they can't be used directly
// with the slt instructions. We could use sub or add instead but we would miss
// overflow cases, so we keep slt and add an intermediate third instruction.
bool MacroAssembler::BranchAndLinkShortHelper(int16_t offset, Label* L,
                                              Condition cond, Register rs,
                                              const Operand& rt,
                                              BranchDelaySlot bdslot) {
  DCHECK(L == nullptr || offset == 0);
  if (!is_near(L, OffsetSize::kOffset16)) return false;

  Register scratch = t8;
  BlockTrampolinePoolScope block_trampoline_pool(this);

  switch (cond) {
    case cc_always:
      offset = GetOffset(offset, L, OffsetSize::kOffset16);
      bal(offset);
      break;
    case eq:
      bne(rs, GetRtAsRegisterHelper(rt, scratch), 2);
      nop();
      offset = GetOffset(offset, L, OffsetSize::kOffset16);
      bal(offset);
      break;
    case ne:
      beq(rs, GetRtAsRegisterHelper(rt, scratch), 2);
      nop();
      offset = GetOffset(offset, L, OffsetSize::kOffset16);
      bal(offset);
      break;

    // Signed comparison.
    case greater:
      Slt(scratch, GetRtAsRegisterHelper(rt, scratch), rs);
      addiu(scratch, scratch, -1);
      offset = GetOffset(offset, L, OffsetSize::kOffset16);
      bgezal(scratch, offset);
      break;
    case greater_equal:
      Slt(scratch, rs, rt);
      addiu(scratch, scratch, -1);
      offset = GetOffset(offset, L, OffsetSize::kOffset16);
      bltzal(scratch, offset);
      break;
    case less:
      Slt(scratch, rs, rt);
      addiu(scratch, scratch, -1);
      offset = GetOffset(offset, L, OffsetSize::kOffset16);
      bgezal(scratch, offset);
      break;
    case less_equal:
      Slt(scratch, GetRtAsRegisterHelper(rt, scratch), rs);
      addiu(scratch, scratch, -1);
      offset = GetOffset(offset, L, OffsetSize::kOffset16);
      bltzal(scratch, offset);
      break;

    // Unsigned comparison.
    case Ugreater:
      Sltu(scratch, GetRtAsRegisterHelper(rt, scratch), rs);
      addiu(scratch, scratch, -1);
      offset = GetOffset(offset, L, OffsetSize::kOffset16);
      bgezal(scratch, offset);
      break;
    case Ugreater_equal:
      Sltu(scratch, rs, rt);
      addiu(scratch, scratch, -1);
      offset = GetOffset(offset, L, OffsetSize::kOffset16);
      bltzal(scratch, offset);
      break;
    case Uless:
      Sltu(scratch, rs, rt);
      addiu(scratch, scratch, -1);
      offset = GetOffset(offset, L, OffsetSize::kOffset16);
      bgezal(scratch, offset);
      break;
    case Uless_equal:
      Sltu(scratch, GetRtAsRegisterHelper(rt, scratch), rs);
      addiu(scratch, scratch, -1);
      offset = GetOffset(offset, L, OffsetSize::kOffset16);
      bltzal(scratch, offset);
      break;

    default:
      UNREACHABLE();
  }

  // Emit a nop in the branch delay slot if required.
  if (bdslot == PROTECT) nop();

  return true;
}

bool MacroAssembler::BranchAndLinkShortCheck(int32_t offset, Label* L,
                                             Condition cond, Register rs,
                                             const Operand& rt,
                                             BranchDelaySlot bdslot) {
  BRANCH_ARGS_CHECK(cond, rs, rt);

  if (!L) {
    if (kArchVariant == kMips64r6 && bdslot == PROTECT) {
      DCHECK(is_int26(offset));
      return BranchAndLinkShortHelperR6(offset, nullptr, cond, rs, rt);
    } else {
      DCHECK(is_int16(offset));
      return BranchAndLinkShortHelper(offset, nullptr, cond, rs, rt, bdslot);
    }
  } else {
    DCHECK_EQ(offset, 0);
    if (kArchVariant == kMips64r6 && bdslot == PROTECT) {
      return BranchAndLinkShortHelperR6(0, L, cond, rs, rt);
    } else {
      return BranchAndLinkShortHelper(0, L, cond, rs, rt, bdslot);
    }
  }
}

void MacroAssembler::LoadFromConstantsTable(Register destination,
                                            int constant_index) {
  ASM_CODE_COMMENT(this);
  DCHECK(RootsTable::IsImmortalImmovable(RootIndex::kBuiltinsConstantsTable));
  LoadRoot(destination, RootIndex::kBuiltinsConstantsTable);
  Ld(destination,
     FieldMemOperand(destination, OFFSET_OF_DATA_START(FixedArray) +
                                      constant_index * kPointerSize));
}

void MacroAssembler::LoadRootRelative(Register destination, int32_t offset) {
  Ld(destination, MemOperand(kRootRegister, offset));
}

void MacroAssembler::StoreRootRelative(int32_t offset, Register value) {
  Sd(value, MemOperand(kRootRegister, offset));
}

void MacroAssembler::LoadRootRegisterOffset(Register destination,
                                            intptr_t offset) {
  if (offset == 0) {
    Move(destination, kRootRegister);
  } else {
    Daddu(destination, kRootRegister, Operand(offset));
  }
}

MemOperand MacroAssembler::ExternalReferenceAsOperand(
    ExternalReference reference, Register scratch) {
  if (root_array_available()) {
    if (reference.IsIsolateFieldId()) {
      return MemOperand(kRootRegister, reference.offset_from_root_register());
    }
    if (options().enable_root_relative_access) {
      int64_t offset =
          RootRegisterOffsetForExternalReference(isolate(), reference);
      if (is_int32(offset)) {
        return MemOperand(kRootRegister, static_cast<int32_t>(offset));
      }
    }
    if (root_array_available_ && options().isolate_independent_code) {
      if (IsAddressableThroughRootRegister(isolate(), reference)) {
        // Some external references can be efficiently loaded as an offset from
        // kRootRegister.
        intptr_t offset =
            RootRegisterOffsetForExternalReference(isolate(), reference);
        CHECK(is_int32(offset));
        return MemOperand(kRootRegister, static_cast<int32_t>(offset));
      } else {
        // Otherwise, do a memory load from the external reference table.
        DCHECK(scratch.is_valid());
        Ld(scratch, MemOperand(kRootRegister,
              
"""


```