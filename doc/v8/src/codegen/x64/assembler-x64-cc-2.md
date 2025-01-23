Response:
The user wants a summary of the functionalities provided by the C++ code snippet from `v8/src/codegen/x64/assembler-x64.cc`.

Here's a breakdown of the thought process:

1. **Identify the core purpose:** The file name `assembler-x64.cc` strongly suggests this code is responsible for assembling x64 machine code instructions. It provides an abstraction layer to emit raw bytes.

2. **Analyze the function names:**  The function names are highly indicative of the x64 assembly instructions they represent (e.g., `pushq`, `mov`, `add`, `jmp`, `test`, `fld`, `movd`, `vmovddup`). This provides a direct mapping to assembly language concepts.

3. **Group functionalities:**  The functions can be grouped based on the types of operations they perform:
    * Stack manipulation (`pushq`, `popq`, `ret`)
    * General-purpose register operations (`mov`, `xchg`, `test`)
    * Control flow (`jmp`, `j`, `call`)
    * Floating-point operations (prefixed with `f`)
    * SSE/AVX instructions (prefixed with `movd`, `movq`, `vmov`)

4. **Look for patterns and common elements:** Notice the `EnsureSpace` calls in almost every function. This suggests memory management for the generated code buffer. The `emit*` functions are responsible for writing the actual bytes. The `emit_rex*` functions deal with instruction prefixes for 64-bit operations.

5. **Address specific user constraints:**
    * **`.tq` extension:**  The code is C++, so it's not a Torque file.
    * **JavaScript relationship:**  Assembler code is low-level and doesn't directly map to high-level JavaScript. The connection is that V8 uses this code to *implement* the execution of JavaScript. An example could involve showing how a simple JavaScript addition translates to assembly instructions.
    * **Code logic inference:**  Choose a simple instruction (like `pushq`) and show how the input (register or immediate value) influences the emitted bytes.
    * **Common programming errors:** Focus on potential errors when interacting with an assembler (like incorrect operand types or sizes).
    * **"Part 3 of 4":**  This implies there are related files. The summary should acknowledge this and suggest that this part likely deals with a subset of the assembler's functionality.

6. **Construct the summary:** Start with a general statement about the file's purpose. Then, list the key functionalities based on the groupings identified earlier. Address each of the user's specific questions with relevant examples and explanations.

7. **Refine and organize:** Ensure the summary is clear, concise, and well-organized. Use bullet points or numbered lists to improve readability. Double-check the examples and explanations for accuracy. Emphasize that this is a low-level component of V8.

**(Self-correction during the process):**

* Initially, I might focus too much on individual instruction details. The user wants a *functional overview*, so grouping and higher-level concepts are more important.
* I might forget to address the JavaScript relationship or the `.tq` extension. It's crucial to go back and ensure all constraints are met.
* The "common programming errors" section needs to be specific to assembler usage, not general JavaScript errors. Misunderstanding operand encoding or register usage are good examples.
* The "code logic inference" needs a clear example with specific inputs and the expected output (emitted bytes).

By following this structured approach and incorporating self-correction, I can generate a comprehensive and accurate summary that addresses all aspects of the user's request.
Based on the provided C++ code snippet from `v8/src/codegen/x64/assembler-x64.cc`, here's a breakdown of its functionality:

**Core Functionality:**

This code defines a part of the `Assembler` class specifically for generating x64 machine code instructions. It provides a set of methods that correspond to various x64 assembly instructions. These methods internally handle the encoding of these instructions into raw byte sequences that can be executed by the processor.

**Specific Functionalities Demonstrated in the Snippet:**

* **Stack Manipulation:**
    * `pushq(Operand src)`: Pushes the value of an operand (register or memory location) onto the stack.
    * `pushq(Immediate value)`: Pushes an immediate value (constant) onto the stack. It handles both 8-bit and larger immediate values.
    * `pushq_imm32(int32_t imm32)`:  Specifically pushes a 32-bit immediate value onto the stack.
    * `pushfq()`: Pushes the contents of the RFLAGS register onto the stack.
    * `incsspq(Register number_of_words)`: Increments the stack pointer (RSP) by a specified number of 8-byte words.
    * `ret(int imm16)`: Returns from a function call, optionally adjusting the stack pointer by a 16-bit immediate value.

* **Control Flow:**
    * `ud2()`:  Generates an "undefined instruction" opcode, often used for debugging or trapping.

* **Conditional Operations:**
    * `setcc(Condition cc, Register reg)`: Sets the lower byte of a register to 1 if the specified condition code (`cc`) is true, and to 0 otherwise.

* **Bit Manipulation:**
    * `shld(Register dst, Register src)`: Performs a double-precision left shift of a destination register using the bits from a source register.
    * `shrd(Register dst, Register src)`: Performs a double-precision right shift of a destination register using the bits from a source register.

* **Data Transfer:**
    * `xchgb(Register reg, Operand op)`: Exchanges the byte value between a register and an operand (register or memory).
    * `xchgw(Register reg, Operand op)`: Exchanges the word value between a register and an operand.
    * `emit_xchg(Register dst, Register src, int size)`:  Emits the appropriate `xchg` instruction for registers based on the size. It has a specific optimization for `rax`.
    * `emit_xchg(Register dst, Operand src, int size)`: Emits the `xchg` instruction between a register and an operand.
    * `store_rax(Address dst, RelocInfo::Mode mode)`: Stores the value of the `rax` register into a memory address.
    * `store_rax(ExternalReference ref)`: Stores the value of `rax` into a memory location pointed to by an external reference.

* **Arithmetic (Subtractions on Stack Pointer):**
    * `sub_sp_32(uint32_t imm)`: Subtracts a 32-bit immediate value from the stack pointer (RSP).

* **Testing:**
    * `testb(Register dst, Register src)`: Performs a bitwise AND operation between two byte registers and sets flags, but doesn't store the result.
    * `testb(Register reg, Immediate mask)`: Performs a bitwise AND between a byte register and an immediate mask.
    * `testb(Operand op, Immediate mask)`: Performs a bitwise AND between an operand and an immediate mask.
    * `testb(Operand op, Register reg)`: Performs a bitwise AND between an operand and a byte register.
    * Similar `testw` functions for word (16-bit) operations.
    * `emit_test(...)`: Internal functions to emit the actual `test` instruction encodings for different operand types and sizes.

* **Floating-Point Unit (FPU) Instructions:**  The code includes a wide range of FPU instructions like:
    * Loading values onto the FPU stack (`fld`, `fld1`, `fldz`, `fldpi`, `fldln2`, `fld_s`, `fld_d`)
    * Storing values from the FPU stack (`fstp_s`, `fstp_d`, `fstp`, `fistp_s`, `fisttp_s`, `fisttp_d`, `fist_s`, `fistp_d`)
    * Arithmetic operations (`fadd`, `fsub`, `fisub_s`, `fmul`, `fdiv`, `faddp`, `fsubp`, `fsubrp`, `fmulp`, `fdivp`)
    * Transcendental functions (`fcos`, `fsin`, `fptan`, `fyl2x`, `f2xm1`, `fscale`)
    * Control and status operations (`fninit`, `fprem`, `fprem1`, `fxch`, `fincstp`, `ffree`, `ftst`, `fucomp`, `fucompp`, `fucomi`, `fucomip`, `fcompp`, `fnstsw_ax`, `fwait`, `frndint`, `fnclex`)
    * Other operations (`fabs`, `fchs`)
    * `emit_farith`: A helper function for emitting certain FPU instructions.

* **Streaming SIMD Extensions 2 (SSE2) Instructions:**
    * Data transfer between XMM registers, general-purpose registers, and memory (`movd`, `movq`, `movdqa`, `movdqu`, `movsd`, `movaps`, `movapd`, `movupd`, `movss`, `movlps`, `movhps`).
    * Packed data operations (`pinsrw`, `pextrq`, `pinsrq`, `pinsrd`, `pinsrb`, `insertps`, `shufps`).
    * Comparison operations (`ucomiss`, `cmpps`, `cmppd`, `cmpeqss`, `cmpeqsd`, `cmpltsd`).
    * Data conversion (`cvtdq2pd`, `cvttss2si`, `cvttsd2si`, `cvttss2siq`, `cvttsd2siq`, `cvttps2dq`, `cvtlsi2sd`, `cvtlsi2ss`, `cvtqsi2ss`, `cvtqsi2sd`, `cvtsd2si`, `cvtsd2siq`).
    * Horizontal operations (`haddps`).
    * Rounding operations (`roundss`, `roundsd`, `roundps`, `roundpd`).
    * Move mask operations (`movmskpd`, `movmskps`, `pmovmskb`).
    * `sse2_instr`:  A helper function for emitting certain SSE2 instructions.

* **Advanced Vector Extensions (AVX) Instructions:**
    * The snippet starts to introduce AVX instructions like `vmovddup` and `vmovshdup` for moving and duplicating data within XMM and YMM registers.
    * `vbroadcastss`: Broadcasting a single value to a vector.

**Is `v8/src/codegen/x64/assembler-x64.cc` a Torque Source File?**

No, the code snippet is in C++. Files ending with `.tq` are V8 Torque source files. Torque is a domain-specific language used within V8 for generating code, often for built-in functions and runtime components.

**Relationship to JavaScript and Examples:**

This C++ code is fundamental to how V8 executes JavaScript on x64 architectures. When V8 compiles JavaScript code, it generates sequences of these x64 assembly instructions.

**Example:**

Consider a simple JavaScript addition:

```javascript
function add(a, b) {
  return a + b;
}
```

When V8 compiles this function for x64, the `Assembler` class (specifically this `assembler-x64.cc` file) would be used to generate instructions like:

```assembly
movq rdi, [rsp + 8]  ; Load the value of 'a' from the stack into register rdi
movq rsi, [rsp + 16] ; Load the value of 'b' from the stack into register rsi
addq rdi, rsi       ; Add the values in rdi and rsi, store the result in rdi
movq rax, rdi       ; Move the result from rdi to rax (return register)
ret                 ; Return from the function
```

The C++ code in `assembler-x64.cc` would contain methods to emit the byte encodings for instructions like `movq`, `addq`, and `ret`. For instance, a simplified version of the `addq` method might look something like:

```c++
void Assembler::addq(Register dst, Register src) {
  EnsureSpace ensure_space(this);
  emit_rex_64(src, dst); // Handle REX prefix for 64-bit registers
  emit(0x01);          // Opcode for add with register as source and destination
  emit_modrm(src, dst); // ModR/M byte to specify registers
}
```

**Code Logic Inference (Example with `pushq(Immediate value)`):**

**Hypothetical Input:** `assembler.pushq(Immediate(10));`

**Code Logic:**

1. The `pushq(Immediate value)` function is called with an immediate value of 10.
2. `is_int8(value.value_)` checks if 10 fits within a signed 8-bit integer. This is true.
3. `emit(0x6A)` emits the opcode for `push` with an 8-bit immediate.
4. `emit(value.value_)` emits the byte representing the value 10.

**Output (Emitted Bytes):** `0x6A 0x0A`

**Hypothetical Input:** `assembler.pushq(Immediate(1000));`

**Code Logic:**

1. The `pushq(Immediate value)` function is called with an immediate value of 1000.
2. `is_int8(value.value_)` checks if 1000 fits within a signed 8-bit integer. This is false.
3. `emit(0x68)` emits the opcode for `push` with a 32-bit immediate.
4. `emitl(value.value_)` emits the 4 bytes representing the 32-bit value 1000 (in little-endian order).

**Output (Emitted Bytes):** `0x68 0xE8 0x03 0x00 0x00` (1000 in hexadecimal is 0x3E8)

**User Common Programming Errors (Relating to Assembler Usage):**

When working directly with an assembler (or code that generates assembly like this), common errors include:

1. **Incorrect Operand Types:**  Trying to use a register when a memory location is required, or vice versa.
   * **Example (Conceptual JavaScript analogy):** Imagine a function expecting a number but you pass it a string. The assembler has similar strict requirements for operand types.

2. **Incorrect Operand Sizes:** Using the wrong instruction variant for the size of the data being manipulated (e.g., using a byte instruction on a 32-bit value).
   * **Example (Conceptual):** Trying to store a large number into a variable that can only hold a small range.

3. **Register Mismatches:** Using registers in a way that violates calling conventions or instruction requirements.
   * **Example (Conceptual):**  Modifying a register that's expected to hold a specific value by another part of the code.

4. **Stack Imbalance:**  Pushing values onto the stack without popping them, leading to stack overflow or corruption.
   * **Example (Conceptual):**  Calling functions recursively without a proper base case.

5. **Incorrect Addressing Modes:**  Using an addressing mode that doesn't correctly calculate the memory location you intend to access.
   * **Example (Conceptual):** Having an incorrect pointer that points to the wrong memory address.

**歸納一下它的功能 (Summary of its Functionality):**

This part of the `assembler-x64.cc` file in V8 provides a C++ interface for emitting x64 machine code instructions. It includes methods for:

* **Basic operations:** Stack manipulation, data transfer, arithmetic (specifically related to the stack pointer), bitwise operations, and control flow.
* **Floating-Point Unit (FPU) instructions:** A comprehensive set of instructions for working with floating-point numbers.
* **Streaming SIMD Extensions 2 (SSE2) instructions:** Instructions for single and double-precision floating-point and integer vector operations.
* **Initial support for Advanced Vector Extensions (AVX) instructions:** Beginning to incorporate instructions for wider vector operations.

Essentially, this code acts as a low-level building block that V8's compiler uses to translate JavaScript code into executable machine instructions for x64 architectures. It handles the complexities of instruction encoding, register usage, and operand specification. This is a crucial component for the performance and execution of JavaScript within the V8 engine.

### 提示词
```
这是目录为v8/src/codegen/x64/assembler-x64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/x64/assembler-x64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
void Assembler::pushq(Operand src) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(src);
  emit(0xFF);
  emit_operand(6, src);
}

void Assembler::pushq(Immediate value) {
  EnsureSpace ensure_space(this);
  if (is_int8(value.value_)) {
    emit(0x6A);
    emit(value.value_);  // Emit low byte of value.
  } else {
    emit(0x68);
    emitl(value.value_);
  }
}

void Assembler::pushq_imm32(int32_t imm32) {
  EnsureSpace ensure_space(this);
  emit(0x68);
  emitl(imm32);
}

void Assembler::pushfq() {
  EnsureSpace ensure_space(this);
  emit(0x9C);
}

void Assembler::incsspq(Register number_of_words) {
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_rex_64(number_of_words);
  emit(0x0F);
  emit(0xAE);
  emit(0xE8 | number_of_words.low_bits());
}

void Assembler::ret(int imm16) {
  EnsureSpace ensure_space(this);
  DCHECK(is_uint16(imm16));
  if (imm16 == 0) {
    emit(0xC3);
  } else {
    emit(0xC2);
    emit(imm16 & 0xFF);
    emit((imm16 >> 8) & 0xFF);
  }
}

void Assembler::ud2() {
  EnsureSpace ensure_space(this);
  emit(0x0F);
  emit(0x0B);
}

void Assembler::setcc(Condition cc, Register reg) {
  EnsureSpace ensure_space(this);
  DCHECK(is_uint4(cc));
  if (!reg.is_byte_register()) {
    // Register is not one of al, bl, cl, dl.  Its encoding needs REX.
    emit_rex_32(reg);
  }
  emit(0x0F);
  emit(0x90 | cc);
  emit_modrm(0x0, reg);
}

void Assembler::shld(Register dst, Register src) {
  EnsureSpace ensure_space(this);
  emit_rex_64(src, dst);
  emit(0x0F);
  emit(0xA5);
  emit_modrm(src, dst);
}

void Assembler::shrd(Register dst, Register src) {
  EnsureSpace ensure_space(this);
  emit_rex_64(src, dst);
  emit(0x0F);
  emit(0xAD);
  emit_modrm(src, dst);
}

void Assembler::xchgb(Register reg, Operand op) {
  EnsureSpace ensure_space(this);
  if (!reg.is_byte_register()) {
    // Register is not one of al, bl, cl, dl.  Its encoding needs REX.
    emit_rex_32(reg, op);
  } else {
    emit_optional_rex_32(reg, op);
  }
  emit(0x86);
  emit_operand(reg, op);
}

void Assembler::xchgw(Register reg, Operand op) {
  EnsureSpace ensure_space(this);
  emit(0x66);
  emit_optional_rex_32(reg, op);
  emit(0x87);
  emit_operand(reg, op);
}

void Assembler::emit_xchg(Register dst, Register src, int size) {
  EnsureSpace ensure_space(this);
  if (src == rax || dst == rax) {  // Single-byte encoding
    Register other = src == rax ? dst : src;
    emit_rex(other, size);
    emit(0x90 | other.low_bits());
  } else if (dst.low_bits() == 4) {
    emit_rex(dst, src, size);
    emit(0x87);
    emit_modrm(dst, src);
  } else {
    emit_rex(src, dst, size);
    emit(0x87);
    emit_modrm(src, dst);
  }
}

void Assembler::emit_xchg(Register dst, Operand src, int size) {
  EnsureSpace ensure_space(this);
  emit_rex(dst, src, size);
  emit(0x87);
  emit_operand(dst, src);
}

void Assembler::store_rax(Address dst, RelocInfo::Mode mode) {
  EnsureSpace ensure_space(this);
  emit(0x48);  // REX.W
  emit(0xA3);
  emit(Immediate64(dst, mode));
}

void Assembler::store_rax(ExternalReference ref) {
  store_rax(ref.address(), RelocInfo::EXTERNAL_REFERENCE);
}

void Assembler::sub_sp_32(uint32_t imm) {
  emit_rex_64();
  emit(0x81);  // using a literal 32-bit immediate.
  emit_modrm(0x5, rsp);
  emitl(imm);
}

void Assembler::testb(Register dst, Register src) {
  EnsureSpace ensure_space(this);
  emit_test(dst, src, sizeof(int8_t));
}

void Assembler::testb(Register reg, Immediate mask) {
  DCHECK(is_int8(mask.value_) || is_uint8(mask.value_));
  emit_test(reg, mask, sizeof(int8_t));
}

void Assembler::testb(Operand op, Immediate mask) {
  DCHECK(is_int8(mask.value_) || is_uint8(mask.value_));
  emit_test(op, mask, sizeof(int8_t));
}

void Assembler::testb(Operand op, Register reg) {
  emit_test(op, reg, sizeof(int8_t));
}

void Assembler::testw(Register dst, Register src) {
  emit_test(dst, src, sizeof(uint16_t));
}

void Assembler::testw(Register reg, Immediate mask) {
  emit_test(reg, mask, sizeof(int16_t));
}

void Assembler::testw(Operand op, Immediate mask) {
  emit_test(op, mask, sizeof(int16_t));
}

void Assembler::testw(Operand op, Register reg) {
  emit_test(op, reg, sizeof(int16_t));
}

void Assembler::emit_test(Register dst, Register src, int size) {
  EnsureSpace ensure_space(this);
  if (src.low_bits() == 4) std::swap(dst, src);
  if (size == sizeof(int16_t)) {
    emit(0x66);
    size = sizeof(int32_t);
  }
  bool byte_operand = size == sizeof(int8_t);
  if (byte_operand) {
    size = sizeof(int32_t);
    if (!src.is_byte_register() || !dst.is_byte_register()) {
      emit_rex_32(dst, src);
    }
  } else {
    emit_rex(dst, src, size);
  }
  emit(byte_operand ? 0x84 : 0x85);
  emit_modrm(dst, src);
}

void Assembler::emit_test(Register reg, Immediate mask, int size) {
  if (is_uint8(mask.value_)) {
    size = sizeof(int8_t);
  } else if (is_uint16(mask.value_)) {
    size = sizeof(int16_t);
  }
  EnsureSpace ensure_space(this);
  bool half_word = size == sizeof(int16_t);
  if (half_word) {
    emit(0x66);
    size = sizeof(int32_t);
  }
  bool byte_operand = size == sizeof(int8_t);
  if (byte_operand) {
    size = sizeof(int32_t);
    if (!reg.is_byte_register()) emit_rex_32(reg);
  } else {
    emit_rex(reg, size);
  }
  if (reg == rax) {
    emit(byte_operand ? 0xA8 : 0xA9);
  } else {
    emit(byte_operand ? 0xF6 : 0xF7);
    emit_modrm(0x0, reg);
  }
  if (byte_operand) {
    emit(mask.value_);
  } else if (half_word) {
    emitw(mask.value_);
  } else {
    emit(mask);
  }
}

void Assembler::emit_test(Operand op, Immediate mask, int size) {
  if (is_uint8(mask.value_)) {
    size = sizeof(int8_t);
  } else if (is_uint16(mask.value_)) {
    size = sizeof(int16_t);
  }
  EnsureSpace ensure_space(this);
  bool half_word = size == sizeof(int16_t);
  if (half_word) {
    emit(0x66);
    size = sizeof(int32_t);
  }
  bool byte_operand = size == sizeof(int8_t);
  if (byte_operand) {
    size = sizeof(int32_t);
  }
  emit_rex(rax, op, size);
  emit(byte_operand ? 0xF6 : 0xF7);
  emit_operand(rax, op);  // Operation code 0
  if (byte_operand) {
    emit(mask.value_);
  } else if (half_word) {
    emitw(mask.value_);
  } else {
    emit(mask);
  }
}

void Assembler::emit_test(Operand op, Register reg, int size) {
  EnsureSpace ensure_space(this);
  if (size == sizeof(int16_t)) {
    emit(0x66);
    size = sizeof(int32_t);
  }
  bool byte_operand = size == sizeof(int8_t);
  if (byte_operand) {
    size = sizeof(int32_t);
    if (!reg.is_byte_register()) {
      // Register is not one of al, bl, cl, dl.  Its encoding needs REX.
      emit_rex_32(reg, op);
    } else {
      emit_optional_rex_32(reg, op);
    }
  } else {
    emit_rex(reg, op, size);
  }
  emit(byte_operand ? 0x84 : 0x85);
  emit_operand(reg, op);
}

// FPU instructions.

void Assembler::fld(int i) {
  EnsureSpace ensure_space(this);
  emit_farith(0xD9, 0xC0, i);
}

void Assembler::fld1() {
  EnsureSpace ensure_space(this);
  emit(0xD9);
  emit(0xE8);
}

void Assembler::fldz() {
  EnsureSpace ensure_space(this);
  emit(0xD9);
  emit(0xEE);
}

void Assembler::fldpi() {
  EnsureSpace ensure_space(this);
  emit(0xD9);
  emit(0xEB);
}

void Assembler::fldln2() {
  EnsureSpace ensure_space(this);
  emit(0xD9);
  emit(0xED);
}

void Assembler::fld_s(Operand adr) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(adr);
  emit(0xD9);
  emit_operand(0, adr);
}

void Assembler::fld_d(Operand adr) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(adr);
  emit(0xDD);
  emit_operand(0, adr);
}

void Assembler::fstp_s(Operand adr) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(adr);
  emit(0xD9);
  emit_operand(3, adr);
}

void Assembler::fstp_d(Operand adr) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(adr);
  emit(0xDD);
  emit_operand(3, adr);
}

void Assembler::fstp(int index) {
  DCHECK(is_uint3(index));
  EnsureSpace ensure_space(this);
  emit_farith(0xDD, 0xD8, index);
}

void Assembler::fild_s(Operand adr) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(adr);
  emit(0xDB);
  emit_operand(0, adr);
}

void Assembler::fild_d(Operand adr) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(adr);
  emit(0xDF);
  emit_operand(5, adr);
}

void Assembler::fistp_s(Operand adr) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(adr);
  emit(0xDB);
  emit_operand(3, adr);
}

void Assembler::fisttp_s(Operand adr) {
  DCHECK(IsEnabled(SSE3));
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(adr);
  emit(0xDB);
  emit_operand(1, adr);
}

void Assembler::fisttp_d(Operand adr) {
  DCHECK(IsEnabled(SSE3));
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(adr);
  emit(0xDD);
  emit_operand(1, adr);
}

void Assembler::fist_s(Operand adr) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(adr);
  emit(0xDB);
  emit_operand(2, adr);
}

void Assembler::fistp_d(Operand adr) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(adr);
  emit(0xDF);
  emit_operand(7, adr);
}

void Assembler::fabs() {
  EnsureSpace ensure_space(this);
  emit(0xD9);
  emit(0xE1);
}

void Assembler::fchs() {
  EnsureSpace ensure_space(this);
  emit(0xD9);
  emit(0xE0);
}

void Assembler::fcos() {
  EnsureSpace ensure_space(this);
  emit(0xD9);
  emit(0xFF);
}

void Assembler::fsin() {
  EnsureSpace ensure_space(this);
  emit(0xD9);
  emit(0xFE);
}

void Assembler::fptan() {
  EnsureSpace ensure_space(this);
  emit(0xD9);
  emit(0xF2);
}

void Assembler::fyl2x() {
  EnsureSpace ensure_space(this);
  emit(0xD9);
  emit(0xF1);
}

void Assembler::f2xm1() {
  EnsureSpace ensure_space(this);
  emit(0xD9);
  emit(0xF0);
}

void Assembler::fscale() {
  EnsureSpace ensure_space(this);
  emit(0xD9);
  emit(0xFD);
}

void Assembler::fninit() {
  EnsureSpace ensure_space(this);
  emit(0xDB);
  emit(0xE3);
}

void Assembler::fadd(int i) {
  EnsureSpace ensure_space(this);
  emit_farith(0xDC, 0xC0, i);
}

void Assembler::fsub(int i) {
  EnsureSpace ensure_space(this);
  emit_farith(0xDC, 0xE8, i);
}

void Assembler::fisub_s(Operand adr) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(adr);
  emit(0xDA);
  emit_operand(4, adr);
}

void Assembler::fmul(int i) {
  EnsureSpace ensure_space(this);
  emit_farith(0xDC, 0xC8, i);
}

void Assembler::fdiv(int i) {
  EnsureSpace ensure_space(this);
  emit_farith(0xDC, 0xF8, i);
}

void Assembler::faddp(int i) {
  EnsureSpace ensure_space(this);
  emit_farith(0xDE, 0xC0, i);
}

void Assembler::fsubp(int i) {
  EnsureSpace ensure_space(this);
  emit_farith(0xDE, 0xE8, i);
}

void Assembler::fsubrp(int i) {
  EnsureSpace ensure_space(this);
  emit_farith(0xDE, 0xE0, i);
}

void Assembler::fmulp(int i) {
  EnsureSpace ensure_space(this);
  emit_farith(0xDE, 0xC8, i);
}

void Assembler::fdivp(int i) {
  EnsureSpace ensure_space(this);
  emit_farith(0xDE, 0xF8, i);
}

void Assembler::fprem() {
  EnsureSpace ensure_space(this);
  emit(0xD9);
  emit(0xF8);
}

void Assembler::fprem1() {
  EnsureSpace ensure_space(this);
  emit(0xD9);
  emit(0xF5);
}

void Assembler::fxch(int i) {
  EnsureSpace ensure_space(this);
  emit_farith(0xD9, 0xC8, i);
}

void Assembler::fincstp() {
  EnsureSpace ensure_space(this);
  emit(0xD9);
  emit(0xF7);
}

void Assembler::ffree(int i) {
  EnsureSpace ensure_space(this);
  emit_farith(0xDD, 0xC0, i);
}

void Assembler::ftst() {
  EnsureSpace ensure_space(this);
  emit(0xD9);
  emit(0xE4);
}

void Assembler::fucomp(int i) {
  EnsureSpace ensure_space(this);
  emit_farith(0xDD, 0xE8, i);
}

void Assembler::fucompp() {
  EnsureSpace ensure_space(this);
  emit(0xDA);
  emit(0xE9);
}

void Assembler::fucomi(int i) {
  EnsureSpace ensure_space(this);
  emit(0xDB);
  emit(0xE8 + i);
}

void Assembler::fucomip() {
  EnsureSpace ensure_space(this);
  emit(0xDF);
  emit(0xE9);
}

void Assembler::fcompp() {
  EnsureSpace ensure_space(this);
  emit(0xDE);
  emit(0xD9);
}

void Assembler::fnstsw_ax() {
  EnsureSpace ensure_space(this);
  emit(0xDF);
  emit(0xE0);
}

void Assembler::fwait() {
  EnsureSpace ensure_space(this);
  emit(0x9B);
}

void Assembler::frndint() {
  EnsureSpace ensure_space(this);
  emit(0xD9);
  emit(0xFC);
}

void Assembler::fnclex() {
  EnsureSpace ensure_space(this);
  emit(0xDB);
  emit(0xE2);
}

void Assembler::sahf() {
  // TODO(X64): Test for presence. Not all 64-bit intel CPU's have sahf
  // in 64-bit mode. Test CpuID.
  DCHECK(IsEnabled(SAHF));
  EnsureSpace ensure_space(this);
  emit(0x9E);
}

void Assembler::emit_farith(int b1, int b2, int i) {
  DCHECK(is_uint8(b1) && is_uint8(b2));  // wrong opcode
  DCHECK(is_uint3(i));                   // illegal stack offset
  emit(b1);
  emit(b2 + i);
}

// SSE 2 operations.

void Assembler::movd(XMMRegister dst, Register src) {
  DCHECK(!IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit(0x66);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x6E);
  emit_sse_operand(dst, src);
}

void Assembler::movd(XMMRegister dst, Operand src) {
  DCHECK(!IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit(0x66);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x6E);
  emit_sse_operand(dst, src);
}

void Assembler::movd(Register dst, XMMRegister src) {
  DCHECK(!IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit(0x66);
  emit_optional_rex_32(src, dst);
  emit(0x0F);
  emit(0x7E);
  emit_sse_operand(src, dst);
}

void Assembler::movq(XMMRegister dst, Register src) {
  // Mixing AVX and non-AVX is expensive, catch those cases
  DCHECK(!IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit(0x66);
  emit_rex_64(dst, src);
  emit(0x0F);
  emit(0x6E);
  emit_sse_operand(dst, src);
}

void Assembler::movq(XMMRegister dst, Operand src) {
  // Mixing AVX and non-AVX is expensive, catch those cases
  DCHECK(!IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit(0x66);
  emit_rex_64(dst, src);
  emit(0x0F);
  emit(0x6E);
  emit_sse_operand(dst, src);
}

void Assembler::movq(Register dst, XMMRegister src) {
  // Mixing AVX and non-AVX is expensive, catch those cases
  DCHECK(!IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit(0x66);
  emit_rex_64(src, dst);
  emit(0x0F);
  emit(0x7E);
  emit_sse_operand(src, dst);
}

void Assembler::movq(XMMRegister dst, XMMRegister src) {
  // Mixing AVX and non-AVX is expensive, catch those cases
  DCHECK(!IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  if (dst.low_bits() == 4) {
    // Avoid unnecessary SIB byte.
    emit(0xF3);
    emit_optional_rex_32(dst, src);
    emit(0x0F);
    emit(0x7E);
    emit_sse_operand(dst, src);
  } else {
    emit(0x66);
    emit_optional_rex_32(src, dst);
    emit(0x0F);
    emit(0xD6);
    emit_sse_operand(src, dst);
  }
}

void Assembler::movdqa(Operand dst, XMMRegister src) {
  EnsureSpace ensure_space(this);
  emit(0x66);
  emit_rex_64(src, dst);
  emit(0x0F);
  emit(0x7F);
  emit_sse_operand(src, dst);
}

void Assembler::movdqa(XMMRegister dst, Operand src) {
  EnsureSpace ensure_space(this);
  emit(0x66);
  emit_rex_64(dst, src);
  emit(0x0F);
  emit(0x6F);
  emit_sse_operand(dst, src);
}

void Assembler::movdqa(XMMRegister dst, XMMRegister src) {
  EnsureSpace ensure_space(this);
  emit(0x66);
  emit_rex_64(src, dst);
  emit(0x0F);
  emit(0x7F);
  emit_sse_operand(src, dst);
}

void Assembler::movdqu(Operand dst, XMMRegister src) {
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_rex_64(src, dst);
  emit(0x0F);
  emit(0x7F);
  emit_sse_operand(src, dst);
}

void Assembler::movdqu(XMMRegister dst, Operand src) {
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_rex_64(dst, src);
  emit(0x0F);
  emit(0x6F);
  emit_sse_operand(dst, src);
}

void Assembler::movdqu(XMMRegister dst, XMMRegister src) {
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_rex_64(dst, src);
  emit(0x0F);
  emit(0x6F);
  emit_sse_operand(dst, src);
}

void Assembler::pinsrw(XMMRegister dst, Register src, uint8_t imm8) {
  EnsureSpace ensure_space(this);
  emit(0x66);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0xC4);
  emit_sse_operand(dst, src);
  emit(imm8);
}

void Assembler::pinsrw(XMMRegister dst, Operand src, uint8_t imm8) {
  EnsureSpace ensure_space(this);
  emit(0x66);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0xC4);
  emit_sse_operand(dst, src);
  emit(imm8);
}

void Assembler::pextrq(Register dst, XMMRegister src, int8_t imm8) {
  DCHECK(IsEnabled(SSE4_1));
  EnsureSpace ensure_space(this);
  emit(0x66);
  emit_rex_64(src, dst);
  emit(0x0F);
  emit(0x3A);
  emit(0x16);
  emit_sse_operand(src, dst);
  emit(imm8);
}

void Assembler::pinsrq(XMMRegister dst, Register src, uint8_t imm8) {
  DCHECK(IsEnabled(SSE4_1));
  EnsureSpace ensure_space(this);
  emit(0x66);
  emit_rex_64(dst, src);
  emit(0x0F);
  emit(0x3A);
  emit(0x22);
  emit_sse_operand(dst, src);
  emit(imm8);
}

void Assembler::pinsrq(XMMRegister dst, Operand src, uint8_t imm8) {
  DCHECK(IsEnabled(SSE4_1));
  EnsureSpace ensure_space(this);
  emit(0x66);
  emit_rex_64(dst, src);
  emit(0x0F);
  emit(0x3A);
  emit(0x22);
  emit_sse_operand(dst, src);
  emit(imm8);
}

void Assembler::pinsrd(XMMRegister dst, Register src, uint8_t imm8) {
  sse4_instr(dst, src, 0x66, 0x0F, 0x3A, 0x22, imm8);
}

void Assembler::pinsrd(XMMRegister dst, Operand src, uint8_t imm8) {
  sse4_instr(dst, src, 0x66, 0x0F, 0x3A, 0x22);
  emit(imm8);
}

void Assembler::pinsrb(XMMRegister dst, Register src, uint8_t imm8) {
  sse4_instr(dst, src, 0x66, 0x0F, 0x3A, 0x20, imm8);
}

void Assembler::pinsrb(XMMRegister dst, Operand src, uint8_t imm8) {
  sse4_instr(dst, src, 0x66, 0x0F, 0x3A, 0x20);
  emit(imm8);
}

void Assembler::insertps(XMMRegister dst, XMMRegister src, uint8_t imm8) {
  DCHECK(is_uint8(imm8));
  sse4_instr(dst, src, 0x66, 0x0F, 0x3A, 0x21);
  emit(imm8);
}

void Assembler::insertps(XMMRegister dst, Operand src, uint8_t imm8) {
  DCHECK(is_uint8(imm8));
  sse4_instr(dst, src, 0x66, 0x0F, 0x3A, 0x21);
  emit(imm8);
}

void Assembler::movsd(Operand dst, XMMRegister src) {
  DCHECK(!IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit(0xF2);  // double
  emit_optional_rex_32(src, dst);
  emit(0x0F);
  emit(0x11);  // store
  emit_sse_operand(src, dst);
}

void Assembler::movsd(XMMRegister dst, XMMRegister src) {
  DCHECK(!IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit(0xF2);  // double
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x10);  // load
  emit_sse_operand(dst, src);
}

void Assembler::movsd(XMMRegister dst, Operand src) {
  DCHECK(!IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit(0xF2);  // double
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x10);  // load
  emit_sse_operand(dst, src);
}

void Assembler::movaps(XMMRegister dst, XMMRegister src) {
  DCHECK(!IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  if (src.low_bits() == 4) {
    // Try to avoid an unnecessary SIB byte.
    emit_optional_rex_32(src, dst);
    emit(0x0F);
    emit(0x29);
    emit_sse_operand(src, dst);
  } else {
    emit_optional_rex_32(dst, src);
    emit(0x0F);
    emit(0x28);
    emit_sse_operand(dst, src);
  }
}

void Assembler::movaps(XMMRegister dst, Operand src) {
  DCHECK(!IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x28);
  emit_sse_operand(dst, src);
}

void Assembler::shufps(XMMRegister dst, XMMRegister src, uint8_t imm8) {
  DCHECK(is_uint8(imm8));
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0xC6);
  emit_sse_operand(dst, src);
  emit(imm8);
}

void Assembler::movapd(XMMRegister dst, XMMRegister src) {
  DCHECK(!IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  if (src.low_bits() == 4) {
    // Try to avoid an unnecessary SIB byte.
    emit(0x66);
    emit_optional_rex_32(src, dst);
    emit(0x0F);
    emit(0x29);
    emit_sse_operand(src, dst);
  } else {
    emit(0x66);
    emit_optional_rex_32(dst, src);
    emit(0x0F);
    emit(0x28);
    emit_sse_operand(dst, src);
  }
}

void Assembler::movupd(XMMRegister dst, Operand src) {
  EnsureSpace ensure_space(this);
  emit(0x66);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x10);
  emit_sse_operand(dst, src);
}

void Assembler::movupd(Operand dst, XMMRegister src) {
  EnsureSpace ensure_space(this);
  emit(0x66);
  emit_optional_rex_32(src, dst);
  emit(0x0F);
  emit(0x11);
  emit_sse_operand(src, dst);
}

void Assembler::ucomiss(XMMRegister dst, XMMRegister src) {
  DCHECK(!IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x2E);
  emit_sse_operand(dst, src);
}

void Assembler::ucomiss(XMMRegister dst, Operand src) {
  DCHECK(!IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x2E);
  emit_sse_operand(dst, src);
}

void Assembler::movss(XMMRegister dst, XMMRegister src) {
  DCHECK(!IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit(0xF3);  // single
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x10);  // load
  emit_sse_operand(dst, src);
}

void Assembler::movss(XMMRegister dst, Operand src) {
  DCHECK(!IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit(0xF3);  // single
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x10);  // load
  emit_sse_operand(dst, src);
}

void Assembler::movss(Operand src, XMMRegister dst) {
  DCHECK(!IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit(0xF3);  // single
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x11);  // store
  emit_sse_operand(dst, src);
}

void Assembler::movlps(XMMRegister dst, Operand src) {
  DCHECK(!IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x12);
  emit_sse_operand(dst, src);
}

void Assembler::movlps(Operand src, XMMRegister dst) {
  DCHECK(!IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x13);
  emit_sse_operand(dst, src);
}

void Assembler::movhps(XMMRegister dst, Operand src) {
  DCHECK(!IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x16);
  emit_sse_operand(dst, src);
}

void Assembler::movhps(Operand src, XMMRegister dst) {
  DCHECK(!IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x17);
  emit_sse_operand(dst, src);
}

void Assembler::cmpps(XMMRegister dst, XMMRegister src, int8_t cmp) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0xC2);
  emit_sse_operand(dst, src);
  emit(cmp);
}

void Assembler::cmpps(XMMRegister dst, Operand src, int8_t cmp) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0xC2);
  emit_sse_operand(dst, src);
  emit(cmp);
}

void Assembler::cmppd(XMMRegister dst, XMMRegister src, int8_t cmp) {
  EnsureSpace ensure_space(this);
  emit(0x66);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0xC2);
  emit_sse_operand(dst, src);
  emit(cmp);
}

void Assembler::cmppd(XMMRegister dst, Operand src, int8_t cmp) {
  EnsureSpace ensure_space(this);
  emit(0x66);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0xC2);
  emit_sse_operand(dst, src);
  emit(cmp);
}

void Assembler::cvtdq2pd(XMMRegister dst, XMMRegister src) {
  sse2_instr(dst, src, 0xF3, 0x0F, 0xE6);
}

void Assembler::cvttss2si(Register dst, Operand src) {
  DCHECK(!IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x2C);
  emit_operand(dst, src);
}

void Assembler::cvttss2si(Register dst, XMMRegister src) {
  DCHECK(!IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x2C);
  emit_sse_operand(dst, src);
}

void Assembler::cvttsd2si(Register dst, Operand src) {
  DCHECK(!IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit(0xF2);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x2C);
  emit_operand(dst, src);
}

void Assembler::cvttsd2si(Register dst, XMMRegister src) {
  DCHECK(!IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit(0xF2);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x2C);
  emit_sse_operand(dst, src);
}

void Assembler::cvttss2siq(Register dst, XMMRegister src) {
  DCHECK(!IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_rex_64(dst, src);
  emit(0x0F);
  emit(0x2C);
  emit_sse_operand(dst, src);
}

void Assembler::cvttss2siq(Register dst, Operand src) {
  DCHECK(!IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_rex_64(dst, src);
  emit(0x0F);
  emit(0x2C);
  emit_sse_operand(dst, src);
}

void Assembler::cvttsd2siq(Register dst, XMMRegister src) {
  DCHECK(!IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit(0xF2);
  emit_rex_64(dst, src);
  emit(0x0F);
  emit(0x2C);
  emit_sse_operand(dst, src);
}

void Assembler::cvttsd2siq(Register dst, Operand src) {
  DCHECK(!IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit(0xF2);
  emit_rex_64(dst, src);
  emit(0x0F);
  emit(0x2C);
  emit_sse_operand(dst, src);
}

void Assembler::cvttps2dq(XMMRegister dst, Operand src) {
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_rex_64(dst, src);
  emit(0x0F);
  emit(0x5B);
  emit_sse_operand(dst, src);
}

void Assembler::cvttps2dq(XMMRegister dst, XMMRegister src) {
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_rex_64(dst, src);
  emit(0x0F);
  emit(0x5B);
  emit_sse_operand(dst, src);
}

void Assembler::cvtlsi2sd(XMMRegister dst, Operand src) {
  DCHECK(!IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit(0xF2);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x2A);
  emit_sse_operand(dst, src);
}

void Assembler::cvtlsi2sd(XMMRegister dst, Register src) {
  DCHECK(!IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit(0xF2);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x2A);
  emit_sse_operand(dst, src);
}

void Assembler::cvtlsi2ss(XMMRegister dst, Operand src) {
  DCHECK(!IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x2A);
  emit_sse_operand(dst, src);
}

void Assembler::cvtlsi2ss(XMMRegister dst, Register src) {
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x2A);
  emit_sse_operand(dst, src);
}

void Assembler::cvtqsi2ss(XMMRegister dst, Operand src) {
  DCHECK(!IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_rex_64(dst, src);
  emit(0x0F);
  emit(0x2A);
  emit_sse_operand(dst, src);
}

void Assembler::cvtqsi2ss(XMMRegister dst, Register src) {
  DCHECK(!IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_rex_64(dst, src);
  emit(0x0F);
  emit(0x2A);
  emit_sse_operand(dst, src);
}

void Assembler::cvtqsi2sd(XMMRegister dst, Operand src) {
  DCHECK(!IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit(0xF2);
  emit_rex_64(dst, src);
  emit(0x0F);
  emit(0x2A);
  emit_sse_operand(dst, src);
}

void Assembler::cvtqsi2sd(XMMRegister dst, Register src) {
  DCHECK(!IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit(0xF2);
  emit_rex_64(dst, src);
  emit(0x0F);
  emit(0x2A);
  emit_sse_operand(dst, src);
}

void Assembler::cvtsd2si(Register dst, XMMRegister src) {
  DCHECK(!IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit(0xF2);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x2D);
  emit_sse_operand(dst, src);
}

void Assembler::cvtsd2siq(Register dst, XMMRegister src) {
  DCHECK(!IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit(0xF2);
  emit_rex_64(dst, src);
  emit(0x0F);
  emit(0x2D);
  emit_sse_operand(dst, src);
}

void Assembler::haddps(XMMRegister dst, XMMRegister src) {
  DCHECK(IsEnabled(SSE3));
  EnsureSpace ensure_space(this);
  emit(0xF2);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x7C);
  emit_sse_operand(dst, src);
}

void Assembler::haddps(XMMRegister dst, Operand src) {
  DCHECK(IsEnabled(SSE3));
  EnsureSpace ensure_space(this);
  emit(0xF2);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x7C);
  emit_sse_operand(dst, src);
}

void Assembler::cmpeqss(XMMRegister dst, XMMRegister src) {
  DCHECK(!IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0xC2);
  emit_sse_operand(dst, src);
  emit(0x00);  // EQ == 0
}

void Assembler::cmpeqsd(XMMRegister dst, XMMRegister src) {
  DCHECK(!IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit(0xF2);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0xC2);
  emit_sse_operand(dst, src);
  emit(0x00);  // EQ == 0
}

void Assembler::cmpltsd(XMMRegister dst, XMMRegister src) {
  EnsureSpace ensure_space(this);
  emit(0xF2);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0xC2);
  emit_sse_operand(dst, src);
  emit(0x01);  // LT == 1
}

void Assembler::roundss(XMMRegister dst, XMMRegister src, RoundingMode mode) {
  DCHECK(!IsEnabled(AVX));
  sse4_instr(dst, src, 0x66, 0x0F, 0x3A, 0x0A);
  // Mask precision exception.
  emit(static_cast<uint8_t>(mode) | 0x8);
}

void Assembler::roundss(XMMRegister dst, Operand src, RoundingMode mode) {
  DCHECK(!IsEnabled(AVX));
  sse4_instr(dst, src, 0x66, 0x0F, 0x3A, 0x0A);
  // Mask precision exception.
  emit(static_cast<uint8_t>(mode) | 0x8);
}

void Assembler::roundsd(XMMRegister dst, XMMRegister src, RoundingMode mode) {
  DCHECK(!IsEnabled(AVX));
  sse4_instr(dst, src, 0x66, 0x0F, 0x3A, 0x0B);
  // Mask precision exception.
  emit(static_cast<uint8_t>(mode) | 0x8);
}

void Assembler::roundsd(XMMRegister dst, Operand src, RoundingMode mode) {
  DCHECK(!IsEnabled(AVX));
  sse4_instr(dst, src, 0x66, 0x0F, 0x3A, 0x0B);
  // Mask precision exception.
  emit(static_cast<uint8_t>(mode) | 0x8);
}

void Assembler::roundps(XMMRegister dst, XMMRegister src, RoundingMode mode) {
  DCHECK(!IsEnabled(AVX));
  sse4_instr(dst, src, 0x66, 0x0F, 0x3A, 0x08);
  // Mask precision exception.
  emit(static_cast<uint8_t>(mode) | 0x8);
}

void Assembler::roundpd(XMMRegister dst, XMMRegister src, RoundingMode mode) {
  DCHECK(!IsEnabled(AVX));
  sse4_instr(dst, src, 0x66, 0x0F, 0x3A, 0x09);
  // Mask precision exception.
  emit(static_cast<uint8_t>(mode) | 0x8);
}

void Assembler::movmskpd(Register dst, XMMRegister src) {
  EnsureSpace ensure_space(this);
  emit(0x66);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x50);
  emit_sse_operand(dst, src);
}

void Assembler::movmskps(Register dst, XMMRegister src) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x50);
  emit_sse_operand(dst, src);
}

void Assembler::pmovmskb(Register dst, XMMRegister src) {
  EnsureSpace ensure_space(this);
  emit(0x66);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0xD7);
  emit_sse_operand(dst, src);
}

// AVX instructions
#define VMOV_DUP(SIMDRegister, length)                            \
  void Assembler::vmovddup(SIMDRegister dst, SIMDRegister src) {  \
    DCHECK(IsEnabled(AVX));                                       \
    EnsureSpace ensure_space(this);                               \
    emit_vex_prefix(dst, xmm0, src, k##length, kF2, k0F, kWIG);   \
    emit(0x12);                                                   \
    emit_sse_operand(dst, src);                                   \
  }                                                               \
                                                                  \
  void Assembler::vmovddup(SIMDRegister dst, Operand src) {       \
    DCHECK(IsEnabled(AVX));                                       \
    EnsureSpace ensure_space(this);                               \
    emit_vex_prefix(dst, xmm0, src, k##length, kF2, k0F, kWIG);   \
    emit(0x12);                                                   \
    emit_sse_operand(dst, src);                                   \
  }                                                               \
                                                                  \
  void Assembler::vmovshdup(SIMDRegister dst, SIMDRegister src) { \
    DCHECK(IsEnabled(AVX));                                       \
    EnsureSpace ensure_space(this);                               \
    emit_vex_prefix(dst, xmm0, src, k##length, kF3, k0F, kWIG);   \
    emit(0x16);                                                   \
    emit_sse_operand(dst, src);                                   \
  }
VMOV_DUP(XMMRegister, L128)
VMOV_DUP(YMMRegister, L256)
#undef VMOV_DUP

#define BROADCAST(suffix, SIMDRegister, length, opcode)                   \
  void Assembler::vbroadcast##suffix(SIMDRegister dst, Operand src) {     \
    DCHECK(IsEnabled(AVX));                                               \
    EnsureSpace ensure_space(this);
```