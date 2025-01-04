Response: The user provided a C++ source code file for the x64 architecture's assembler in the V8 JavaScript engine. It's the second part of the file. The goal is to summarize the functionality of this code and illustrate its relationship with JavaScript using examples.

**Breakdown of the Code:**

The code consists of a large number of methods within the `Assembler` class. Each method corresponds to a specific x64 assembly instruction. The methods do the following:

1. **`EnsureSpace`:**  Most methods start with this. It's responsible for making sure there's enough space in the internal buffer to emit the instruction.
2. **Emit Byte Code:**  The core functionality of each method is to emit the raw byte code representation of the corresponding x64 instruction. This involves:
    - Opcode bytes (e.g., `0xFF` for `pushq`).
    - ModR/M byte (specifies operands - registers or memory locations).
    - SIB byte (for complex memory addressing).
    - Immediate values (constants).
    - REX prefixes (for 64-bit operations or extended registers).
    - VEX prefixes (for AVX instructions).
3. **Operand Encoding:** Helper methods like `emit_operand`, `emit_sse_operand`, and `emit_modrm` are used to correctly encode the operands of the instructions.
4. **Instruction-Specific Logic:** Some methods have specific logic based on the instruction's requirements, such as handling different immediate sizes or register types.
5. **FPU Instructions:** A section deals with instructions for the x87 floating-point unit (FPU).
6. **SSE/AVX Instructions:** A significant portion covers instructions for the Streaming SIMD Extensions (SSE) and Advanced Vector Extensions (AVX) for vectorized operations.
7. **BMI/LZCNT/POPCNT:**  Instructions for bit manipulation and counting.
8. **Relocation Information:**  The code interacts with `RelocInfo` to record information about memory addresses that need to be updated during linking or loading (e.g., jumps to other code).

**Relationship with JavaScript:**

This `Assembler` class is a fundamental part of V8's compilation pipeline. When V8 compiles JavaScript code, it translates it into machine code for the target architecture (x64 in this case). The `Assembler` class provides the interface for generating that machine code.

Here's how it connects to JavaScript:

1. **JIT Compilation:** V8 uses Just-In-Time (JIT) compilation. When a JavaScript function is executed, V8 might compile it into optimized machine code.
2. **Code Generation:** The `Assembler` class is used within the JIT compiler to emit the actual x64 instructions that perform the operations defined in the JavaScript code.
3. **Low-Level Operations:** Instructions like `pushq`, `mov`, `add`, `call`, `ret`, and the SIMD instructions correspond to basic computational and control flow operations needed to execute JavaScript.
4. **Optimization:**  Optimizations in V8 often involve generating efficient sequences of assembly instructions. For example, array manipulations might use SSE/AVX instructions for parallel processing.

**JavaScript Examples:**

Let's illustrate with some simple JavaScript examples and how they might relate to the assembly instructions in the code:

* **Variable Assignment:**

```javascript
let x = 10;
```

This might involve a `movq` instruction to move the immediate value `10` into a register or memory location associated with the variable `x`.

* **Arithmetic Operation:**

```javascript
let y = x + 5;
```

This could translate to an `addq` instruction to add the immediate value `5` to the register/memory holding `x`, and then another `movq` to store the result in `y`.

* **Function Call:**

```javascript
function foo() {
  return 20;
}
let z = foo();
```

The call to `foo()` would likely involve a `call` instruction to jump to the compiled code of `foo`, and the `return` statement would use a `mov` instruction to place the return value (20) in a specific register (often `rax`) and then a `ret` instruction to return.

* **Array Manipulation (Potential SSE/AVX usage):**

```javascript
let arr1 = [1, 2, 3, 4];
let arr2 = arr1.map(n => n * 2);
```

The `.map()` operation, especially for numerical arrays, might be optimized to use SSE/AVX instructions to multiply multiple array elements in parallel. Instructions like `vmovdqa` (to load array elements into SIMD registers) and `vpslld` (vectorized shift left for multiplication by 2) could be used.

* **Conditional Statements:**

```javascript
if (x > 5) {
  // ...
}
```

This would involve a comparison instruction (like `cmpq`), followed by a conditional jump instruction (like `jle` - jump if less than or equal to) to skip the code block if the condition is false. The `setcc` instruction could be used to set a register based on the result of the comparison.

**Summary of Functionality:**

This part of `assembler-x64.cc` provides methods for emitting a wide range of x64 assembly instructions, including:

- **General-purpose instructions:** Data movement (`mov`), stack operations (`push`, `pop`), arithmetic and logical operations (`add`, `sub`, `and`, `or`), control flow (`jmp`, `call`, `ret`).
- **Floating-point instructions (x87 FPU):**  Loading, storing, arithmetic, and transcendental functions for floating-point numbers.
- **SIMD instructions (SSE and AVX):**  Instructions for performing parallel operations on vectors of data, used for optimizing numerical computations and other data-intensive tasks.
- **Bit manipulation instructions (BMI, LZCNT, POPCNT):** Instructions for advanced bitwise operations.
- **Relocation handling:** Mechanisms to record information needed for linking and loading the generated code.

Essentially, this file is a low-level building block of the V8 JavaScript engine, enabling the generation of efficient machine code from JavaScript source.
这是 `v8/src/codegen/x64/assembler-x64.cc` 文件的第二部分，延续了第一部分的功能，**主要负责提供更多 x64 汇编指令的封装，用于在 V8 引擎中动态生成机器码。**

与第一部分类似，这部分代码也定义了 `Assembler` 类的方法，每个方法对应一个或一组 x64 汇编指令。这些方法允许 V8 的代码生成器方便地发出底层的机器指令，从而实现 JavaScript 代码的执行。

**这部分的功能主要集中在以下几个方面：**

1. **栈操作指令:**  `pushq`, `pushfq`, `incsspq`, `ret` 等，用于管理函数调用栈。
2. **条件设置指令:** `setcc`，根据标志寄存器的状态设置目标寄存器的值。
3. **位移指令:** `shld`, `shrd`，执行带进位的位移操作。
4. **交换指令:** `xchgb`, `xchgw`, `emit_xchg`，用于交换寄存器或内存中的数据。
5. **数据存储指令:** `store_rax`，将 `rax` 寄存器的值存储到内存地址。
6. **栈指针操作指令:** `sub_sp_32`，用于调整栈指针。
7. **测试指令:** `testb`, `testw`, `emit_test`，用于执行按位与操作并设置标志寄存器，但不修改操作数。
8. **浮点指令 (FPU):**  大量以 `f` 开头的指令，例如 `fld`, `fstp`, `fadd`, `fmul` 等，用于执行浮点运算。
9. **SIMD 指令 (SSE/AVX):**  大量以 `movd`, `movq`, `movaps`, `vmovd`, `vaddps` 等开头的指令，用于执行单指令多数据 (SIMD) 操作，提高并行计算能力。这些指令涵盖了各种数据类型的移动、算术运算、比较、类型转换等。
10. **BMI, LZCNT, POPCNT 等指令:**  用于执行位操作和计数操作。
11. **其他杂项指令:** `ud2` (触发非法指令异常), `pause` (提示处理器优化性能) 等。
12. **数据定义指令:** `db`, `dd`, `dq`，用于在代码段中定义字节、双字、四字数据。
13. **标签处理:**  `dq(Label* label)`, `WriteBuiltinJumpTableEntry`, `WriteBuiltinJumpTableInfos`，用于处理代码中的标签和跳转表。
14. **重定位信息记录:** `RecordRelocInfo`，用于记录需要在链接或加载时进行调整的地址信息。

**与 JavaScript 功能的关系及示例:**

这部分代码提供的汇编指令是 V8 执行 JavaScript 代码的基础。当 V8 编译 JavaScript 代码时，会将高级的 JavaScript 语句转换为这些底层的 x64 汇编指令。

以下是一些 JavaScript 功能可能用到的指令示例：

* **变量赋值和算术运算:**

```javascript
let a = 10;
let b = 5;
let c = a + b;
```

这可能会用到 `movq` 指令将立即数 `10` 和 `5` 加载到寄存器，然后使用 `addq` 指令进行加法运算，最后再用 `movq` 将结果存储到 `c` 对应的内存位置。

* **函数调用:**

```javascript
function add(x, y) {
  return x + y;
}
let result = add(3, 7);
```

函数调用会用到 `pushq` 指令将参数压入栈，`call` 指令跳转到 `add` 函数的代码，函数内部可能使用 `mov` 和 `add` 指令进行计算，最后使用 `ret` 指令返回。

* **条件语句:**

```javascript
let num = 8;
if (num > 5) {
  console.log("Greater than 5");
}
```

`if` 语句会用到比较指令（例如 `cmpq`）比较 `num` 和 `5`，然后使用条件跳转指令（例如 `jg` - jump if greater）来决定是否执行 `console.log` 的代码。`setcc` 指令也可能用于设置基于比较结果的标志位。

* **数组操作和数值计算 (SIMD 指令):**

```javascript
let arr = [1, 2, 3, 4];
let doubled = arr.map(x => x * 2);
```

对于数组的批量操作，V8 可能会使用 SSE/AVX 指令，例如 `movdqa` 或 `vmovdqa` 将数组元素加载到 XMM/YMM 寄存器，然后使用 `pmullw` 或 `vpmullw` 等 SIMD 乘法指令进行并行计算。

* **浮点数运算:**

```javascript
let pi = 3.14;
let radius = 5.0;
let area = pi * radius * radius;
```

涉及到浮点数运算时，会使用 FPU 指令，例如 `fld` 加载浮点数到 FPU 寄存器，`fmul` 执行乘法运算，`fstp` 将结果存储回内存。

总而言之，这部分 `assembler-x64.cc` 代码是 V8 引擎将 JavaScript 代码转化为可执行机器码的关键组成部分，提供了丰富的指令支持，涵盖了各种常见的计算、内存操作和控制流需求，并且针对性能优化，集成了 SIMD 和 FPU 指令的支持。

Prompt: 
```
这是目录为v8/src/codegen/x64/assembler-x64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""


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
    EnsureSpace ensure_space(this);                                       \
    emit_vex_prefix(dst, xmm0, src, k##length, k66, k0F38, kW0);          \
    emit(0x##opcode);                                                     \
    emit_sse_operand(dst, src);                                           \
  }                                                                       \
  void Assembler::vbroadcast##suffix(SIMDRegister dst, XMMRegister src) { \
    DCHECK(IsEnabled(AVX2));                                              \
    EnsureSpace ensure_space(this);                                       \
    emit_vex_prefix(dst, xmm0, src, k##length, k66, k0F38, kW0);          \
    emit(0x##opcode);                                                     \
    emit_sse_operand(dst, src);                                           \
  }
BROADCAST(ss, XMMRegister, L128, 18)
BROADCAST(ss, YMMRegister, L256, 18)
BROADCAST(sd, YMMRegister, L256, 19)
#undef BROADCAST

void Assembler::vinserti128(YMMRegister dst, YMMRegister src1, XMMRegister src2,
                            uint8_t imm8) {
  DCHECK(IsEnabled(AVX2));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, src1, src2, kL256, k66, k0F3A, kW0);
  emit(0x38);
  emit_sse_operand(dst, src2);
  emit(imm8);
}

void Assembler::vperm2f128(YMMRegister dst, YMMRegister src1, YMMRegister src2,
                           uint8_t imm8) {
  DCHECK(IsEnabled(AVX));
  DCHECK(is_uint8(imm8));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, src1, src2, kL256, k66, k0F3A, kW0);
  emit(0x06);
  emit_sse_operand(dst, src2);
  emit(imm8);
}

void Assembler::vextractf128(XMMRegister dst, YMMRegister src, uint8_t imm8) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(src, xmm0, dst, kL256, k66, k0F3A, kW0);
  emit(0x19);
  emit_sse_operand(src, dst);
  emit(imm8);
}

template <typename Reg1, typename Reg2, typename Op>
void Assembler::fma_instr(uint8_t op, Reg1 dst, Reg2 src1, Op src2,
                          VectorLength l, SIMDPrefix pp, LeadingOpcode m,
                          VexW w) {
  DCHECK(IsEnabled(FMA3));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, src1, src2, l, pp, m, w);
  emit(op);
  emit_sse_operand(dst, src2);
}

template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE) void Assembler::fma_instr(
    uint8_t op, XMMRegister dst, XMMRegister src1, XMMRegister src2,
    VectorLength l, SIMDPrefix pp, LeadingOpcode m, VexW w);

template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE) void Assembler::fma_instr(
    uint8_t op, YMMRegister dst, YMMRegister src1, YMMRegister src2,
    VectorLength l, SIMDPrefix pp, LeadingOpcode m, VexW w);

template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE) void Assembler::fma_instr(
    uint8_t op, XMMRegister dst, XMMRegister src1, Operand src2, VectorLength l,
    SIMDPrefix pp, LeadingOpcode m, VexW w);

template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE) void Assembler::fma_instr(
    uint8_t op, YMMRegister dst, YMMRegister src1, Operand src2, VectorLength l,
    SIMDPrefix pp, LeadingOpcode m, VexW w);

void Assembler::vmovd(XMMRegister dst, Register src) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  XMMRegister isrc = XMMRegister::from_code(src.code());
  emit_vex_prefix(dst, xmm0, isrc, kL128, k66, k0F, kW0);
  emit(0x6E);
  emit_sse_operand(dst, src);
}

void Assembler::vmovd(XMMRegister dst, Operand src) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, xmm0, src, kL128, k66, k0F, kW0);
  emit(0x6E);
  emit_sse_operand(dst, src);
}

void Assembler::vmovd(Register dst, XMMRegister src) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  XMMRegister idst = XMMRegister::from_code(dst.code());
  emit_vex_prefix(src, xmm0, idst, kL128, k66, k0F, kW0);
  emit(0x7E);
  emit_sse_operand(src, dst);
}

void Assembler::vmovq(XMMRegister dst, Register src) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  XMMRegister isrc = XMMRegister::from_code(src.code());
  emit_vex_prefix(dst, xmm0, isrc, kL128, k66, k0F, kW1);
  emit(0x6E);
  emit_sse_operand(dst, src);
}

void Assembler::vmovq(XMMRegister dst, Operand src) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, xmm0, src, kL128, k66, k0F, kW1);
  emit(0x6E);
  emit_sse_operand(dst, src);
}

void Assembler::vmovq(Register dst, XMMRegister src) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  XMMRegister idst = XMMRegister::from_code(dst.code());
  emit_vex_prefix(src, xmm0, idst, kL128, k66, k0F, kW1);
  emit(0x7E);
  emit_sse_operand(src, dst);
}

void Assembler::vmovdqa(XMMRegister dst, Operand src) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, xmm0, src, kL128, k66, k0F, kWIG);
  emit(0x6F);
  emit_sse_operand(dst, src);
}

void Assembler::vmovdqa(XMMRegister dst, XMMRegister src) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, xmm0, src, kL128, k66, k0F, kWIG);
  emit(0x6F);
  emit_sse_operand(dst, src);
}

void Assembler::vmovdqa(YMMRegister dst, Operand src) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, ymm0, src, kL256, k66, k0F, kWIG);
  emit(0x6F);
  emit_sse_operand(dst, src);
}

void Assembler::vmovdqa(YMMRegister dst, YMMRegister src) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, ymm0, src, kL256, k66, k0F, kWIG);
  emit(0x6F);
  emit_sse_operand(dst, src);
}

void Assembler::vmovdqu(XMMRegister dst, Operand src) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, xmm0, src, kL128, kF3, k0F, kWIG);
  emit(0x6F);
  emit_sse_operand(dst, src);
}

void Assembler::vmovdqu(Operand dst, XMMRegister src) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(src, xmm0, dst, kL128, kF3, k0F, kWIG);
  emit(0x7F);
  emit_sse_operand(src, dst);
}

void Assembler::vmovdqu(XMMRegister dst, XMMRegister src) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(src, xmm0, dst, kL128, kF3, k0F, kWIG);
  emit(0x7F);
  emit_sse_operand(src, dst);
}

void Assembler::vmovdqu(YMMRegister dst, Operand src) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, ymm0, src, kL256, kF3, k0F, kWIG);
  emit(0x6F);
  emit_sse_operand(dst, src);
}

void Assembler::vmovdqu(Operand dst, YMMRegister src) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(src, ymm0, dst, kL256, kF3, k0F, kWIG);
  emit(0x7F);
  emit_sse_operand(src, dst);
}

void Assembler::vmovdqu(YMMRegister dst, YMMRegister src) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(src, ymm0, dst, kL256, kF3, k0F, kWIG);
  emit(0x7F);
  emit_sse_operand(src, dst);
}

void Assembler::vmovlps(XMMRegister dst, XMMRegister src1, Operand src2) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, src1, src2, kL128, kNoPrefix, k0F, kWIG);
  emit(0x12);
  emit_sse_operand(dst, src2);
}

void Assembler::vmovlps(Operand dst, XMMRegister src) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(src, xmm0, dst, kL128, kNoPrefix, k0F, kWIG);
  emit(0x13);
  emit_sse_operand(src, dst);
}

void Assembler::vmovhps(XMMRegister dst, XMMRegister src1, Operand src2) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, src1, src2, kL128, kNoPrefix, k0F, kWIG);
  emit(0x16);
  emit_sse_operand(dst, src2);
}

void Assembler::vmovhps(Operand dst, XMMRegister src) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(src, xmm0, dst, kL128, kNoPrefix, k0F, kWIG);
  emit(0x17);
  emit_sse_operand(src, dst);
}

void Assembler::vinstr(uint8_t op, XMMRegister dst, XMMRegister src1,
                       XMMRegister src2, SIMDPrefix pp, LeadingOpcode m, VexW w,
                       CpuFeature feature) {
  DCHECK(IsEnabled(feature));
  DCHECK(feature == AVX || feature == AVX2 || feature == AVX_VNNI ||
         feature == AVX_VNNI_INT8);
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, src1, src2, kLIG, pp, m, w);
  emit(op);
  emit_sse_operand(dst, src2);
}

void Assembler::vinstr(uint8_t op, XMMRegister dst, XMMRegister src1,
                       Operand src2, SIMDPrefix pp, LeadingOpcode m, VexW w,
                       CpuFeature feature) {
  DCHECK(IsEnabled(feature));
  DCHECK(feature == AVX || feature == AVX2);
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, src1, src2, kLIG, pp, m, w);
  emit(op);
  emit_sse_operand(dst, src2);
}

template <typename Reg1, typename Reg2, typename Op>
void Assembler::vinstr(uint8_t op, Reg1 dst, Reg2 src1, Op src2, SIMDPrefix pp,
                       LeadingOpcode m, VexW w, CpuFeature feature) {
  DCHECK(IsEnabled(feature));
  DCHECK(feature == AVX || feature == AVX2 || feature == AVX_VNNI ||
         feature == AVX_VNNI_INT8);
  DCHECK(
      (std::is_same_v<Reg1, YMMRegister> || std::is_same_v<Reg2, YMMRegister>));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, src1, src2, kL256, pp, m, w);
  emit(op);
  emit_sse_operand(dst, src2);
}

template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE) void Assembler::vinstr(
    uint8_t op, YMMRegister dst, YMMRegister src1, YMMRegister src2,
    SIMDPrefix pp, LeadingOpcode m, VexW w, CpuFeature feature);
template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE) void Assembler::vinstr(
    uint8_t op, YMMRegister dst, XMMRegister src1, XMMRegister src2,
    SIMDPrefix pp, LeadingOpcode m, VexW w, CpuFeature feature);
template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE) void Assembler::vinstr(
    uint8_t op, YMMRegister dst, YMMRegister src1, Operand src2, SIMDPrefix pp,
    LeadingOpcode m, VexW w, CpuFeature feature);
template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE) void Assembler::vinstr(
    uint8_t op, YMMRegister dst, YMMRegister src1, XMMRegister src2,
    SIMDPrefix pp, LeadingOpcode m, VexW w, CpuFeature feature);
template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE) void Assembler::vinstr(
    uint8_t op, YMMRegister dst, XMMRegister src1, Operand src2, SIMDPrefix pp,
    LeadingOpcode m, VexW w, CpuFeature feature);
template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE) void Assembler::vinstr(
    uint8_t op, YMMRegister dst, XMMRegister src1, YMMRegister src2,
    SIMDPrefix pp, LeadingOpcode m, VexW w, CpuFeature feature);

void Assembler::vps(uint8_t op, XMMRegister dst, XMMRegister src1,
                    XMMRegister src2) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, src1, src2, kL128, kNoPrefix, k0F, kWIG);
  emit(op);
  emit_sse_operand(dst, src2);
}

void Assembler::vps(uint8_t op, YMMRegister dst, YMMRegister src1,
                    YMMRegister src2) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, src1, src2, kL256, kNoPrefix, k0F, kWIG);
  emit(op);
  emit_sse_operand(dst, src2);
}

void Assembler::vps(uint8_t op, XMMRegister dst, XMMRegister src1,
                    Operand src2) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, src1, src2, kL128, kNoPrefix, k0F, kWIG);
  emit(op);
  emit_sse_operand(dst, src2);
}

void Assembler::vps(uint8_t op, YMMRegister dst, YMMRegister src1,
                    Operand src2) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, src1, src2, kL256, kNoPrefix, k0F, kWIG);
  emit(op);
  emit_sse_operand(dst, src2);
}

void Assembler::vps(uint8_t op, XMMRegister dst, XMMRegister src1,
                    XMMRegister src2, uint8_t imm8) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, src1, src2, kL128, kNoPrefix, k0F, kWIG);
  emit(op);
  emit_sse_operand(dst, src2);
  emit(imm8);
}

void Assembler::vps(uint8_t op, YMMRegister dst, YMMRegister src1,
                    YMMRegister src2, uint8_t imm8) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, src1, src2, kL256, kNoPrefix, k0F, kWIG);
  emit(op);
  emit_sse_operand(dst, src2);
  emit(imm8);
}

#define VPD(DSTRegister, SRCRegister, length)                        \
  void Assembler::vpd(uint8_t op, DSTRegister dst, SRCRegister src1, \
                      SRCRegister src2) {                            \
    DCHECK(IsEnabled(AVX));                                          \
    EnsureSpace ensure_space(this);                                  \
    emit_vex_prefix(dst, src1, src2, k##length, k66, k0F, kWIG);     \
    emit(op);                                                        \
    emit_sse_operand(dst, src2);                                     \
  }                                                                  \
                                                                     \
  void Assembler::vpd(uint8_t op, DSTRegister dst, SRCRegister src1, \
                      Operand src2) {                                \
    DCHECK(IsEnabled(AVX));                                          \
    EnsureSpace ensure_space(this);                                  \
    emit_vex_prefix(dst, src1, src2, k##length, k66, k0F, kWIG);     \
    emit(op);                                                        \
    emit_sse_operand(dst, src2);                                     \
  }
VPD(XMMRegister, XMMRegister, L128)
VPD(XMMRegister, YMMRegister, L256)
VPD(YMMRegister, YMMRegister, L256)
#undef VPD

#define F16C(Dst, Src, Pref, Op, PP, Tmp)             \
  DCHECK(IsEnabled(F16C));                            \
  EnsureSpace ensure_space(this);                     \
  emit_vex_prefix(Dst, Tmp, Src, PP, k66, Pref, kW0); \
  emit(Op);                                           \
  emit_sse_operand(Dst, Src);

void Assembler::vcvtph2ps(XMMRegister dst, XMMRegister src) {
  F16C(dst, src, k0F38, 0x13, kLIG, xmm0);
}

void Assembler::vcvtph2ps(YMMRegister dst, XMMRegister src) {
  F16C(dst, src, k0F38, 0x13, kL256, ymm0);
}

void Assembler::vcvtps2ph(XMMRegister dst, YMMRegister src, uint8_t imm8) {
  F16C(src, dst, k0F3A, 0x1D, kL256, xmm0);
  emit(imm8);
}

void Assembler::vcvtps2ph(XMMRegister dst, XMMRegister src, uint8_t imm8) {
  F16C(src, dst, k0F3A, 0x1D, kLIG, ymm0);
  emit(imm8);
}

#undef F16C

void Assembler::vucomiss(XMMRegister dst, XMMRegister src) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, xmm0, src, kLIG, kNoPrefix, k0F, kWIG);
  emit(0x2E);
  emit_sse_operand(dst, src);
}

void Assembler::vucomiss(XMMRegister dst, Operand src) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, xmm0, src, kLIG, kNoPrefix, k0F, kWIG);
  emit(0x2E);
  emit_sse_operand(dst, src);
}

void Assembler::vpmovmskb(Register dst, XMMRegister src) {
  XMMRegister idst = XMMRegister::from_code(dst.code());
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(idst, xmm0, src, kL128, k66, k0F, kWIG);
  emit(0xD7);
  emit_sse_operand(idst, src);
}

void Assembler::vss(uint8_t op, XMMRegister dst, XMMRegister src1,
                    XMMRegister src2) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, src1, src2, kLIG, kF3, k0F, kWIG);
  emit(op);
  emit_sse_operand(dst, src2);
}

void Assembler::vss(uint8_t op, XMMRegister dst, XMMRegister src1,
                    Operand src2) {
  DCHECK(IsEnabled(AVX));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, src1, src2, kLIG, kF3, k0F, kWIG);
  emit(op);
  emit_sse_operand(dst, src2);
}

void Assembler::bmi1q(uint8_t op, Register reg, Register vreg, Register rm) {
  DCHECK(IsEnabled(BMI1));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(reg, vreg, rm, kLZ, kNoPrefix, k0F38, kW1);
  emit(op);
  emit_modrm(reg, rm);
}

void Assembler::bmi1q(uint8_t op, Register reg, Register vreg, Operand rm) {
  DCHECK(IsEnabled(BMI1));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(reg, vreg, rm, kLZ, kNoPrefix, k0F38, kW1);
  emit(op);
  emit_operand(reg, rm);
}

void Assembler::bmi1l(uint8_t op, Register reg, Register vreg, Register rm) {
  DCHECK(IsEnabled(BMI1));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(reg, vreg, rm, kLZ, kNoPrefix, k0F38, kW0);
  emit(op);
  emit_modrm(reg, rm);
}

void Assembler::bmi1l(uint8_t op, Register reg, Register vreg, Operand rm) {
  DCHECK(IsEnabled(BMI1));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(reg, vreg, rm, kLZ, kNoPrefix, k0F38, kW0);
  emit(op);
  emit_operand(reg, rm);
}

void Assembler::tzcntq(Register dst, Register src) {
  DCHECK(IsEnabled(BMI1));
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_rex_64(dst, src);
  emit(0x0F);
  emit(0xBC);
  emit_modrm(dst, src);
}

void Assembler::tzcntq(Register dst, Operand src) {
  DCHECK(IsEnabled(BMI1));
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_rex_64(dst, src);
  emit(0x0F);
  emit(0xBC);
  emit_operand(dst, src);
}

void Assembler::tzcntl(Register dst, Register src) {
  DCHECK(IsEnabled(BMI1));
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0xBC);
  emit_modrm(dst, src);
}

void Assembler::tzcntl(Register dst, Operand src) {
  DCHECK(IsEnabled(BMI1));
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0xBC);
  emit_operand(dst, src);
}

void Assembler::lzcntq(Register dst, Register src) {
  DCHECK(IsEnabled(LZCNT));
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_rex_64(dst, src);
  emit(0x0F);
  emit(0xBD);
  emit_modrm(dst, src);
}

void Assembler::lzcntq(Register dst, Operand src) {
  DCHECK(IsEnabled(LZCNT));
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_rex_64(dst, src);
  emit(0x0F);
  emit(0xBD);
  emit_operand(dst, src);
}

void Assembler::lzcntl(Register dst, Register src) {
  DCHECK(IsEnabled(LZCNT));
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0xBD);
  emit_modrm(dst, src);
}

void Assembler::lzcntl(Register dst, Operand src) {
  DCHECK(IsEnabled(LZCNT));
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0xBD);
  emit_operand(dst, src);
}

void Assembler::popcntq(Register dst, Register src) {
  DCHECK(IsEnabled(POPCNT));
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_rex_64(dst, src);
  emit(0x0F);
  emit(0xB8);
  emit_modrm(dst, src);
}

void Assembler::popcntq(Register dst, Operand src) {
  DCHECK(IsEnabled(POPCNT));
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_rex_64(dst, src);
  emit(0x0F);
  emit(0xB8);
  emit_operand(dst, src);
}

void Assembler::popcntl(Register dst, Register src) {
  DCHECK(IsEnabled(POPCNT));
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0xB8);
  emit_modrm(dst, src);
}

void Assembler::popcntl(Register dst, Operand src) {
  DCHECK(IsEnabled(POPCNT));
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0xB8);
  emit_operand(dst, src);
}

void Assembler::bmi2q(SIMDPrefix pp, uint8_t op, Register reg, Register vreg,
                      Register rm) {
  DCHECK(IsEnabled(BMI2));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(reg, vreg, rm, kLZ, pp, k0F38, kW1);
  emit(op);
  emit_modrm(reg, rm);
}

void Assembler::bmi2q(SIMDPrefix pp, uint8_t op, Register reg, Register vreg,
                      Operand rm) {
  DCHECK(IsEnabled(BMI2));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(reg, vreg, rm, kLZ, pp, k0F38, kW1);
  emit(op);
  emit_operand(reg, rm);
}

void Assembler::bmi2l(SIMDPrefix pp, uint8_t op, Register reg, Register vreg,
                      Register rm) {
  DCHECK(IsEnabled(BMI2));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(reg, vreg, rm, kLZ, pp, k0F38, kW0);
  emit(op);
  emit_modrm(reg, rm);
}

void Assembler::bmi2l(SIMDPrefix pp, uint8_t op, Register reg, Register vreg,
                      Operand rm) {
  DCHECK(IsEnabled(BMI2));
  EnsureSpace ensure_space(this);
  emit_vex_prefix(reg, vreg, rm, kLZ, pp, k0F38, kW0);
  emit(op);
  emit_operand(reg, rm);
}

void Assembler::rorxq(Register dst, Register src, uint8_t imm8) {
  DCHECK(IsEnabled(BMI2));
  DCHECK(is_uint8(imm8));
  Register vreg = Register::from_code(0);  // VEX.vvvv unused
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, vreg, src, kLZ, kF2, k0F3A, kW1);
  emit(0xF0);
  emit_modrm(dst, src);
  emit(imm8);
}

void Assembler::rorxq(Register dst, Operand src, uint8_t imm8) {
  DCHECK(IsEnabled(BMI2));
  DCHECK(is_uint8(imm8));
  Register vreg = Register::from_code(0);  // VEX.vvvv unused
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, vreg, src, kLZ, kF2, k0F3A, kW1);
  emit(0xF0);
  emit_operand(dst, src);
  emit(imm8);
}

void Assembler::rorxl(Register dst, Register src, uint8_t imm8) {
  DCHECK(IsEnabled(BMI2));
  DCHECK(is_uint8(imm8));
  Register vreg = Register::from_code(0);  // VEX.vvvv unused
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, vreg, src, kLZ, kF2, k0F3A, kW0);
  emit(0xF0);
  emit_modrm(dst, src);
  emit(imm8);
}

void Assembler::rorxl(Register dst, Operand src, uint8_t imm8) {
  DCHECK(IsEnabled(BMI2));
  DCHECK(is_uint8(imm8));
  Register vreg = Register::from_code(0);  // VEX.vvvv unused
  EnsureSpace ensure_space(this);
  emit_vex_prefix(dst, vreg, src, kLZ, kF2, k0F3A, kW0);
  emit(0xF0);
  emit_operand(dst, src);
  emit(imm8);
}

void Assembler::pause() {
  emit(0xF3);
  emit(0x90);
}

void Assembler::movups(XMMRegister dst, XMMRegister src) {
  EnsureSpace ensure_space(this);
  if (src.low_bits() == 4) {
    // Try to avoid an unnecessary SIB byte.
    emit_optional_rex_32(src, dst);
    emit(0x0F);
    emit(0x11);
    emit_sse_operand(src, dst);
  } else {
    emit_optional_rex_32(dst, src);
    emit(0x0F);
    emit(0x10);
    emit_sse_operand(dst, src);
  }
}

void Assembler::movups(XMMRegister dst, Operand src) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x10);
  emit_sse_operand(dst, src);
}

void Assembler::movups(Operand dst, XMMRegister src) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(src, dst);
  emit(0x0F);
  emit(0x11);
  emit_sse_operand(src, dst);
}

void Assembler::sse_instr(XMMRegister dst, XMMRegister src, uint8_t escape,
                          uint8_t opcode) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(dst, src);
  emit(escape);
  emit(opcode);
  emit_sse_operand(dst, src);
}

void Assembler::sse_instr(XMMRegister dst, Operand src, uint8_t escape,
                          uint8_t opcode) {
  EnsureSpace ensure_space(this);
  emit_optional_rex_32(dst, src);
  emit(escape);
  emit(opcode);
  emit_sse_operand(dst, src);
}

void Assembler::sse2_instr(XMMRegister dst, XMMRegister src, uint8_t prefix,
                           uint8_t escape, uint8_t opcode) {
  EnsureSpace ensure_space(this);
  emit(prefix);
  emit_optional_rex_32(dst, src);
  emit(escape);
  emit(opcode);
  emit_sse_operand(dst, src);
}

void Assembler::sse2_instr(XMMRegister dst, Operand src, uint8_t prefix,
                           uint8_t escape, uint8_t opcode) {
  EnsureSpace ensure_space(this);
  emit(prefix);
  emit_optional_rex_32(dst, src);
  emit(escape);
  emit(opcode);
  emit_sse_operand(dst, src);
}

void Assembler::ssse3_instr(XMMRegister dst, XMMRegister src, uint8_t prefix,
                            uint8_t escape1, uint8_t escape2, uint8_t opcode) {
  DCHECK(IsEnabled(SSSE3));
  EnsureSpace ensure_space(this);
  emit(prefix);
  emit_optional_rex_32(dst, src);
  emit(escape1);
  emit(escape2);
  emit(opcode);
  emit_sse_operand(dst, src);
}

void Assembler::ssse3_instr(XMMRegister dst, Operand src, uint8_t prefix,
                            uint8_t escape1, uint8_t escape2, uint8_t opcode) {
  DCHECK(IsEnabled(SSSE3));
  EnsureSpace ensure_space(this);
  emit(prefix);
  emit_optional_rex_32(dst, src);
  emit(escape1);
  emit(escape2);
  emit(opcode);
  emit_sse_operand(dst, src);
}

void Assembler::sse4_instr(XMMRegister dst, Register src, uint8_t prefix,
                           uint8_t escape1, uint8_t escape2, uint8_t opcode,
                           int8_t imm8) {
  DCHECK(is_uint8(imm8));
  DCHECK(IsEnabled(SSE4_1));
  EnsureSpace ensure_space(this);
  emit(prefix);
  emit_optional_rex_32(dst, src);
  emit(escape1);
  emit(escape2);
  emit(opcode);
  emit_sse_operand(dst, src);
  emit(imm8);
}

void Assembler::sse4_instr(XMMRegister dst, XMMRegister src, uint8_t prefix,
                           uint8_t escape1, uint8_t escape2, uint8_t opcode) {
  DCHECK(IsEnabled(SSE4_1));
  EnsureSpace ensure_space(this);
  emit(prefix);
  emit_optional_rex_32(dst, src);
  emit(escape1);
  emit(escape2);
  emit(opcode);
  emit_sse_operand(dst, src);
}

void Assembler::sse4_instr(XMMRegister dst, Operand src, uint8_t prefix,
                           uint8_t escape1, uint8_t escape2, uint8_t opcode) {
  DCHECK(IsEnabled(SSE4_1));
  EnsureSpace ensure_space(this);
  emit(prefix);
  emit_optional_rex_32(dst, src);
  emit(escape1);
  emit(escape2);
  emit(opcode);
  emit_sse_operand(dst, src);
}

void Assembler::sse4_instr(Register dst, XMMRegister src, uint8_t prefix,
                           uint8_t escape1, uint8_t escape2, uint8_t opcode,
                           int8_t imm8) {
  DCHECK(is_uint8(imm8));
  DCHECK(IsEnabled(SSE4_1));
  EnsureSpace ensure_space(this);
  emit(prefix);
  emit_optional_rex_32(src, dst);
  emit(escape1);
  emit(escape2);
  emit(opcode);
  emit_sse_operand(src, dst);
  emit(imm8);
}

void Assembler::sse4_instr(Operand dst, XMMRegister src, uint8_t prefix,
                           uint8_t escape1, uint8_t escape2, uint8_t opcode,
                           int8_t imm8) {
  DCHECK(is_uint8(imm8));
  DCHECK(IsEnabled(SSE4_1));
  EnsureSpace ensure_space(this);
  emit(prefix);
  emit_optional_rex_32(src, dst);
  emit(escape1);
  emit(escape2);
  emit(opcode);
  emit_sse_operand(src, dst);
  emit(imm8);
}

void Assembler::sse4_2_instr(XMMRegister dst, XMMRegister src, uint8_t prefix,
                             uint8_t escape1, uint8_t escape2, uint8_t opcode) {
  DCHECK(IsEnabled(SSE4_2));
  EnsureSpace ensure_space(this);
  emit(prefix);
  emit_optional_rex_32(dst, src);
  emit(escape1);
  emit(escape2);
  emit(opcode);
  emit_sse_operand(dst, src);
}

void Assembler::sse4_2_instr(XMMRegister dst, Operand src, uint8_t prefix,
                             uint8_t escape1, uint8_t escape2, uint8_t opcode) {
  DCHECK(IsEnabled(SSE4_2));
  EnsureSpace ensure_space(this);
  emit(prefix);
  emit_optional_rex_32(dst, src);
  emit(escape1);
  emit(escape2);
  emit(opcode);
  emit_sse_operand(dst, src);
}

void Assembler::lddqu(XMMRegister dst, Operand src) {
  DCHECK(IsEnabled(SSE3));
  EnsureSpace ensure_space(this);
  emit(0xF2);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0xF0);
  emit_sse_operand(dst, src);
}

void Assembler::movddup(XMMRegister dst, XMMRegister src) {
  DCHECK(IsEnabled(SSE3));
  EnsureSpace ensure_space(this);
  emit(0xF2);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x12);
  emit_sse_operand(dst, src);
}

void Assembler::movddup(XMMRegister dst, Operand src) {
  DCHECK(IsEnabled(SSE3));
  EnsureSpace ensure_space(this);
  emit(0xF2);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x12);
  emit_sse_operand(dst, src);
}

void Assembler::movshdup(XMMRegister dst, XMMRegister src) {
  DCHECK(IsEnabled(SSE3));
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x16);
  emit_sse_operand(dst, src);
}

void Assembler::psrldq(XMMRegister dst, uint8_t shift) {
  EnsureSpace ensure_space(this);
  emit(0x66);
  emit_optional_rex_32(dst);
  emit(0x0F);
  emit(0x73);
  emit_sse_operand(dst);
  emit(shift);
}

void Assembler::pshufhw(XMMRegister dst, XMMRegister src, uint8_t shuffle) {
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x70);
  emit_sse_operand(dst, src);
  emit(shuffle);
}

void Assembler::pshufhw(XMMRegister dst, Operand src, uint8_t shuffle) {
  EnsureSpace ensure_space(this);
  emit(0xF3);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x70);
  emit_sse_operand(dst, src);
  emit(shuffle);
}

void Assembler::pshuflw(XMMRegister dst, XMMRegister src, uint8_t shuffle) {
  EnsureSpace ensure_space(this);
  emit(0xF2);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x70);
  emit_sse_operand(dst, src);
  emit(shuffle);
}

void Assembler::pshuflw(XMMRegister dst, Operand src, uint8_t shuffle) {
  EnsureSpace ensure_space(this);
  emit(0xF2);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x70);
  emit_sse_operand(dst, src);
  emit(shuffle);
}

void Assembler::pshufd(XMMRegister dst, XMMRegister src, uint8_t shuffle) {
  EnsureSpace ensure_space(this);
  emit(0x66);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x70);
  emit_sse_operand(dst, src);
  emit(shuffle);
}

void Assembler::pshufd(XMMRegister dst, Operand src, uint8_t shuffle) {
  EnsureSpace ensure_space(this);
  emit(0x66);
  emit_optional_rex_32(dst, src);
  emit(0x0F);
  emit(0x70);
  emit_sse_operand(dst, src);
  emit(shuffle);
}

void Assembler::emit_sse_operand(XMMRegister reg, Operand adr) {
  Register ireg = Register::from_code(reg.code());
  emit_operand(ireg, adr);
}

void Assembler::emit_sse_operand(Register reg, Operand adr) {
  emit_operand(reg, adr);
}

void Assembler::emit_sse_operand(XMMRegister dst, XMMRegister src) {
  emit(0xC0 | (dst.low_bits() << 3) | src.low_bits());
}

void Assembler::emit_sse_operand(XMMRegister dst, Register src) {
  emit(0xC0 | (dst.low_bits() << 3) | src.low_bits());
}

void Assembler::emit_sse_operand(Register dst, XMMRegister src) {
  emit(0xC0 | (dst.low_bits() << 3) | src.low_bits());
}

void Assembler::emit_sse_operand(XMMRegister dst) {
  emit(0xD8 | dst.low_bits());
}

void Assembler::db(uint8_t data) {
  EnsureSpace ensure_space(this);
  emit(data);
}

void Assembler::dd(uint32_t data) {
  EnsureSpace ensure_space(this);
  emitl(data);
}

void Assembler::dq(uint64_t data) {
  EnsureSpace ensure_space(this);
  emitq(data);
}

void Assembler::dq(Label* label) {
  EnsureSpace ensure_space(this);
  if (label->is_bound()) {
    internal_reference_positions_.push_back(pc_offset());
    emit(Immediate64(reinterpret_cast<Address>(buffer_start_) + label->pos(),
                     RelocInfo::INTERNAL_REFERENCE));
  } else {
    RecordRelocInfo(RelocInfo::INTERNAL_REFERENCE);
    emitl(0);  // Zero for the first 32bit marks it as 64bit absolute address.
    if (label->is_linked()) {
      emitl(label->pos());
      label->link_to(pc_offset() - sizeof(int32_t));
    } else {
      DCHECK(label->is_unused());
      int32_t current = pc_offset();
      emitl(current);
      label->link_to(current);
    }
  }
}

void Assembler::WriteBuiltinJumpTableEntry(Label* label, int table_pos) {
  EnsureSpace ensure_space(this);
  CHECK(label->is_bound());
  int32_t value = label->pos() - table_pos;
  if constexpr (V8_BUILTIN_JUMP_TABLE_INFO_BOOL) {
    builtin_jump_table_info_writer_.Add(pc_offset(), label->pos());
  }
  emitl(value);
}

int Assembler::WriteBuiltinJumpTableInfos() {
  if (builtin_jump_table_info_writer_.entry_count() == 0) return 0;
  CHECK(V8_BUILTIN_JUMP_TABLE_INFO_BOOL);
  int offset = pc_offset();
  builtin_jump_table_info_writer_.Emit(this);
  int size = pc_offset() - offset;
  DCHECK_EQ(size, builtin_jump_table_info_writer_.size_in_bytes());
  return size;
}

// Relocation information implementations.

void Assembler::RecordRelocInfo(RelocInfo::Mode rmode, intptr_t data) {
  if (!ShouldRecordRelocInfo(rmode)) return;
  RelocInfo rinfo(reinterpret_cast<Address>(pc_), rmode, data);
  reloc_info_writer.Write(&rinfo);
}

const int RelocInfo::kApplyMask =
    RelocInfo::ModeMask(RelocInfo::CODE_TARGET) |
    RelocInfo::ModeMask(RelocInfo::NEAR_BUILTIN_ENTRY) |
    RelocInfo::ModeMask(RelocInfo::INTERNAL_REFERENCE) |
    RelocInfo::ModeMask(RelocInfo::WASM_CALL) |
    RelocInfo::ModeMask(RelocInfo::WASM_STUB_CALL);

bool RelocInfo::IsCodedSpecially() {
  // The deserializer needs to know whether a pointer is specially coded.  Being
  // specially coded on x64 means that it is a relative 32 bit address, as used
  // by branch instructions.
  return (1 << rmode_) & kApplyMask;
}

bool RelocInfo::IsInConstantPool() { return false; }

}  // namespace internal
}  // namespace v8

#endif  // V8_TARGET_ARCH_X64

"""


```