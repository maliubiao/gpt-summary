Response:
The user wants a summary of the provided C++ code snippet, which is part of V8's macro-assembler for the PowerPC architecture. I need to identify the functionalities implemented in this part of the code. Specifically, the user is interested in:

1. **General Functionality**: What does this code do?
2. **Torque Source**:  Could this be a Torque file? (Answer: No, it's `.cc`)
3. **JavaScript Relation**: Does this code relate to JavaScript functionality? If so, provide an example.
4. **Code Logic Inference**: Are there logical deductions happening?  Give an example with input and output.
5. **Common Programming Errors**:  Does the code help prevent common errors?  Give examples.
6. **Overall Summary**: A concise recap of the code's purpose.

**Analysis of the Code Snippet:**

The code primarily defines methods within the `MacroAssembler` class for the PPC architecture. These methods provide an abstraction layer over the raw PPC assembly instructions, making it easier to generate machine code. Key functionalities include:

* **Function Calls**: Calling C functions.
* **Memory Access**: Loading and storing data of various sizes (8, 16, 32, 64 bits, floats, doubles, SIMD vectors) from memory, with and without updates to the base register. Endianness considerations are present.
* **Literal Loading**: Loading integer, Smi (small integer), and double literals into registers.
* **Data Conversion**: Converting between integer and floating-point representations.
* **Arithmetic Operations**: Performing addition, subtraction, multiplication, division, and modulus operations for both signed and unsigned integers (32 and 64 bits).
* **Bitwise Operations**: Performing AND, OR, XOR operations.
* **Shift Operations**:  Left and right shifts (logical and arithmetic).
* **Comparisons**: Comparing integer values (signed and unsigned, 32 and 64 bits) and Smi values.
* **Floating-Point Operations**: Addition, subtraction, multiplication, division, and copying the sign for double-precision floating-point numbers. Single-precision operations are also present, often involving conversion to double and back.
* **Page Flag Checking**: Checking flags associated with memory pages.
* **Rounding Mode Control**: Setting and resetting the floating-point rounding mode.

**JavaScript Relation Example:**

Many of these operations directly support the implementation of JavaScript's core functionalities. For example, arithmetic operations are fundamental to evaluating JavaScript expressions.

**Code Logic Inference Example:**

The `CheckPageFlag` function performs a logical AND operation and then checks the result. Input: a memory address (`object`), a mask (`mask`). Output: branch to `condition_met` if the specified bits in the memory page's flags match the condition.

**Common Programming Errors Example:**

The code helps manage memory access and provides type-safe operations. A common error it mitigates is incorrect memory addressing. For instance, the `LoadU64` functions ensure that 64-bit values are loaded correctly. Without such helpers, manual assembly could lead to misaligned access, causing crashes.

**Overall Summary:**

This section of `macro-assembler-ppc.cc` provides a collection of methods that generate PPC assembly instructions for common operations required by the V8 JavaScript engine. It handles memory access, arithmetic, bitwise operations, data conversions, and floating-point manipulations.

**Final Plan:**

1. State that the code is for the PPC macro-assembler.
2. Confirm it's not Torque.
3. Provide a JavaScript example relating to arithmetic operations.
4. Give an example for `CheckPageFlag` with hypothetical input and output.
5. Explain how type-safe operations help prevent memory access errors with an example like `LoadU64`.
6. Summarize that it's a collection of methods generating PPC assembly for V8.
```
这个v8源代码文件 `v8/src/codegen/ppc/macro-assembler-ppc.cc` 是V8 JavaScript引擎中用于PowerPC (PPC) 架构的宏汇编器实现。宏汇编器提供了一层抽象，允许开发者用更高级的接口来生成底层的机器码指令，从而简化了代码生成过程。

**功能列举:**

1. **C函数调用:** 提供了调用C++函数的功能，可以设置是否需要设置isolate数据槽以及是否有函数描述符。
2. **页标志检查:**  `CheckPageFlag` 函数用于检查指定内存页的标志位是否满足特定条件。
3. **浮点舍入模式控制:**  提供了设置和重置浮点运算舍入模式的功能。
4. **加载字面量:**  可以加载整型、SMI（Small Integer，V8中用于表示小整数的特殊类型）和双精度浮点数字面量到寄存器。针对双精度浮点数，还考虑了常量池的优化。
5. **数据类型转换:** 提供了在整型和双精度浮点数之间进行转换的功能，包括有符号和无符号整数。还支持将64位整数拆分或组合成双精度浮点数。
6. **位域操作:**  提供了插入双精度浮点数的低位和高位的功能。
7. **浮点数到整数的转换:** 提供了将双精度浮点数的低位和高位转换为整数的功能。
8. **64位和32位整数的算术运算:** 实现了64位和32位有符号整数的加法、减法、乘法、除法和取模运算。
9. **64位和32位无符号整数的位运算:** 实现了64位和32位无符号整数的与、或、异或运算。
10. **移位操作:** 提供了64位和32位整数的左移、右移（逻辑和算术）操作。
11. **比较操作:**  实现了64位和32位有符号和无符号整数的比较操作，以及SMI字面量的比较。
12. **浮点运算:** 提供了双精度和单精度浮点数的加法、减法、乘法、除法和符号复制操作。
13. **SMI字面量操作:** 提供了SMI字面量的比较、加法、减法和与运算。
14. **内存操作:**  提供了各种加载和存储指令，支持不同大小的数据类型（8位、16位、32位、64位、浮点数、SIMD），并考虑了对齐和原子性（带Update后缀的指令）。针对大小端序提供了特定的指令（带有LE后缀）。
15. **SIMD操作:** 提供了加载和存储SIMD（单指令多数据流）寄存器的指令。

**关于文件后缀和Torque:**

`v8/src/codegen/ppc/macro-assembler-ppc.cc` 的后缀是 `.cc`，这表明它是一个C++源代码文件。如果文件以 `.tq` 结尾，那么它才是一个V8 Torque源代码文件。Torque是V8用于定义运行时内置函数和类型系统的领域特定语言。

**与JavaScript功能的关联和JavaScript示例:**

`macro-assembler-ppc.cc` 中定义的功能是JavaScript引擎执行的基础。许多JavaScript操作最终都会被编译成类似的机器码指令。

例如，JavaScript中的加法操作 `a + b` 如果 `a` 和 `b` 是数字，可能会在底层使用 `MacroAssembler::AddS64` 或 `MacroAssembler::AddF64` 等函数生成相应的PPC汇编指令。

```javascript
function add(a, b) {
  return a + b;
}

console.log(add(5, 3)); // 输出 8
console.log(add(2.5, 1.5)); // 输出 4
```

当V8执行 `add(5, 3)` 时，如果 `5` 和 `3` 被表示为SMI，宏汇编器可能会使用 `AddSmiLiteral` 或者 `AddS32` 指令。而执行 `add(2.5, 1.5)` 时，由于涉及到浮点数，宏汇编器可能会使用 `AddF64` 指令。

**代码逻辑推理示例:**

**假设输入:**

* `object` 寄存器包含内存地址 `0x1000`
* `scratch` 寄存器可以与 `object` 寄存器相同
* `mask` 为 `0x4` (二进制 `00000100`)
* `cc` 为 `ne` (不等于)
* 假设在地址 `0x1000` 的内存块的标志位偏移处 (`MemoryChunk::FlagsOffset()`) 的值为 `0x5` (二进制 `00000101`)

**代码逻辑推理:**

1. `ClearRightImm(scratch, object, Operand(kPageSizeBits))`：假设 `kPageSizeBits` 是 12，这会清除 `object` 地址的低12位，但由于 `object` 本身就是页对齐的，所以 `scratch` 仍然是 `0x1000`。
2. `LoadU64(scratch, MemOperand(scratch, MemoryChunk::FlagsOffset()), r0)`：从地址 `0x1000 + MemoryChunk::FlagsOffset()` 加载一个64位无符号整数到 `scratch` 寄存器。假设 `MemoryChunk::FlagsOffset()` 为 0，则加载 `0x5` 到 `scratch`。
3. `mov(r0, Operand(mask))`：将 `mask` 的值 `0x4` 加载到寄存器 `r0`。
4. `and_(r0, scratch, r0, SetRC)`：执行按位与操作，`r0` 的新值为 `0x4 & 0x5 = 0x4`。 `SetRC` 表示设置条件寄存器。
5. `bne(condition_met, cr0)`：检查条件寄存器 `cr0` 中与“不等于零”相关的位。由于 `r0` 的结果 `0x4` 不为零，并且 `cc` 是 `ne`，所以会跳转到 `condition_met` 标签。

**输出:** 如果上述假设成立，代码会跳转到 `condition_met` 标签。

**用户常见的编程错误示例:**

1. **类型不匹配的内存访问:**  例如，尝试用 `LoadU32` 加载一个实际上是64位的值，或者反过来。宏汇编器提供的类型化的加载/存储指令可以帮助避免这类错误。
   ```c++
   // 错误示例：假设 address 指向一个 64 位整数
   uint32_t value;
   masm->LoadU32(r3, MemOperand(r4, address_offset)); // 可能只加载了低 32 位

   // 正确示例
   uint64_t value;
   masm->LoadU64(r3, MemOperand(r4, address_offset));
   ```

2. **错误的寄存器使用:**  在某些指令中，源寄存器和目标寄存器不能相同，或者某些寄存器有特殊用途。宏汇编器可以对这些约束进行一定的封装和检查，减少直接编写汇编代码时的错误。

3. **忽略大小端序问题:** 在跨平台或者处理网络数据时，大小端序是一个常见的问题。`macro-assembler-ppc.cc` 提供了带有 `LE` 后缀的指令来处理小端序数据，开发者如果直接操作内存可能会忘记处理。

**第4部分功能归纳:**

这部分 `v8/src/codegen/ppc/macro-assembler-ppc.cc` 代码主要定义了 `MacroAssembler` 类中用于执行各种基本操作的方法，包括：

* **函数调用和页标志检查等控制流操作。**
* **加载和操作各种数据类型的字面量。**
* **在整数和浮点数之间进行转换。**
* **执行基本的算术、位运算和移位操作。**
* **进行数值比较。**
* **执行浮点数运算。**
* **提供不同类型的内存加载和存储指令，包括对SIMD和大小端序的支持。**

这些方法为V8引擎在PPC架构上生成高效的机器码提供了基础 building blocks。它们抽象了底层的汇编指令，使得代码生成器可以更方便地生成正确的代码，并减少了手动编写汇编代码时容易出现的错误。

### 提示词
```
这是目录为v8/src/codegen/ppc/macro-assembler-ppc.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/ppc/macro-assembler-ppc.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
SetIsolateDataSlots set_isolate_data_slots,
                                  bool has_function_descriptor) {
  return CallCFunction(function, num_arguments, 0, set_isolate_data_slots,
                       has_function_descriptor);
}

int MacroAssembler::CallCFunction(Register function, int num_arguments,
                                  SetIsolateDataSlots set_isolate_data_slots,
                                  bool has_function_descriptor) {
  return CallCFunction(function, num_arguments, 0, set_isolate_data_slots,
                       has_function_descriptor);
}

void MacroAssembler::CheckPageFlag(
    Register object,
    Register scratch,  // scratch may be same register as object
    int mask, Condition cc, Label* condition_met) {
  DCHECK(cc == ne || cc == eq);
  DCHECK(scratch != r0);
  ClearRightImm(scratch, object, Operand(kPageSizeBits));
  LoadU64(scratch, MemOperand(scratch, MemoryChunk::FlagsOffset()), r0);

  mov(r0, Operand(mask));
  and_(r0, scratch, r0, SetRC);

  if (cc == ne) {
    bne(condition_met, cr0);
  }
  if (cc == eq) {
    beq(condition_met, cr0);
  }
}

void MacroAssembler::SetRoundingMode(FPRoundingMode RN) { mtfsfi(7, RN); }

void MacroAssembler::ResetRoundingMode() {
  mtfsfi(7, kRoundToNearest);  // reset (default is kRoundToNearest)
}

////////////////////////////////////////////////////////////////////////////////
//
// New MacroAssembler Interfaces added for PPC
//
////////////////////////////////////////////////////////////////////////////////
void MacroAssembler::LoadIntLiteral(Register dst, int value) {
  mov(dst, Operand(value));
}

void MacroAssembler::LoadSmiLiteral(Register dst, Tagged<Smi> smi) {
  mov(dst, Operand(smi));
}

void MacroAssembler::LoadDoubleLiteral(DoubleRegister result,
                                       base::Double value, Register scratch) {
  if (V8_EMBEDDED_CONSTANT_POOL_BOOL && is_constant_pool_available() &&
      !(scratch == r0 && ConstantPoolAccessIsInOverflow())) {
    ConstantPoolEntry::Access access = ConstantPoolAddEntry(value);
    if (access == ConstantPoolEntry::OVERFLOWED) {
      addis(scratch, kConstantPoolRegister, Operand::Zero());
      lfd(result, MemOperand(scratch, 0));
    } else {
      lfd(result, MemOperand(kConstantPoolRegister, 0));
    }
    return;
  }

  // avoid gcc strict aliasing error using union cast
  union {
    uint64_t dval;
    intptr_t ival;
  } litVal;

  litVal.dval = value.AsUint64();

  mov(scratch, Operand(litVal.ival));
  mtfprd(result, scratch);
}

void MacroAssembler::MovIntToDouble(DoubleRegister dst, Register src,
                                    Register scratch) {
  // sign-extend src to 64-bit
  mtfprwa(dst, src);
}

void MacroAssembler::MovUnsignedIntToDouble(DoubleRegister dst, Register src,
                                            Register scratch) {
  // zero-extend src to 64-bit
  mtfprwz(dst, src);
}

void MacroAssembler::MovInt64ToDouble(DoubleRegister dst,
                                      Register src) {
  mtfprd(dst, src);
}

void MacroAssembler::MovInt64ComponentsToDouble(DoubleRegister dst,
                                                Register src_hi,
                                                Register src_lo,
                                                Register scratch) {
  ShiftLeftU64(scratch, src_hi, Operand(32));
  rldimi(scratch, src_lo, 0, 32);
  mtfprd(dst, scratch);
}

void MacroAssembler::InsertDoubleLow(DoubleRegister dst, Register src,
                                     Register scratch) {
  mffprd(scratch, dst);
  rldimi(scratch, src, 0, 32);
  mtfprd(dst, scratch);
}

void MacroAssembler::InsertDoubleHigh(DoubleRegister dst, Register src,
                                      Register scratch) {
  mffprd(scratch, dst);
  rldimi(scratch, src, 32, 0);
  mtfprd(dst, scratch);
}

void MacroAssembler::MovDoubleLowToInt(Register dst, DoubleRegister src) {
  mffprwz(dst, src);
}

void MacroAssembler::MovDoubleHighToInt(Register dst, DoubleRegister src) {
  mffprd(dst, src);
  srdi(dst, dst, Operand(32));
}

void MacroAssembler::MovDoubleToInt64(Register dst, DoubleRegister src) {
  mffprd(dst, src);
}

void MacroAssembler::MovIntToFloat(DoubleRegister dst, Register src,
                                   Register scratch) {
  ShiftLeftU64(scratch, src, Operand(32));
  mtfprd(dst, scratch);
  xscvspdpn(dst, dst);
}

void MacroAssembler::MovFloatToInt(Register dst, DoubleRegister src,
                                   DoubleRegister scratch) {
  xscvdpspn(scratch, src);
  mffprwz(dst, scratch);
}

void MacroAssembler::AddS64(Register dst, Register src, Register value, OEBit s,
                            RCBit r) {
  add(dst, src, value, s, r);
}

void MacroAssembler::AddS64(Register dst, Register src, const Operand& value,
                            Register scratch, OEBit s, RCBit r) {
  if (is_int16(value.immediate()) && s == LeaveOE && r == LeaveRC) {
    addi(dst, src, value);
  } else {
    mov(scratch, value);
    add(dst, src, scratch, s, r);
  }
}

void MacroAssembler::SubS64(Register dst, Register src, Register value, OEBit s,
                            RCBit r) {
  sub(dst, src, value, s, r);
}

void MacroAssembler::SubS64(Register dst, Register src, const Operand& value,
                            Register scratch, OEBit s, RCBit r) {
  if (is_int16(value.immediate()) && s == LeaveOE && r == LeaveRC) {
    subi(dst, src, value);
  } else {
    mov(scratch, value);
    sub(dst, src, scratch, s, r);
  }
}

void MacroAssembler::AddS32(Register dst, Register src, Register value,
                            RCBit r) {
  AddS64(dst, src, value, LeaveOE, r);
  extsw(dst, dst, r);
}

void MacroAssembler::AddS32(Register dst, Register src, const Operand& value,
                            Register scratch, RCBit r) {
  AddS64(dst, src, value, scratch, LeaveOE, r);
  extsw(dst, dst, r);
}

void MacroAssembler::SubS32(Register dst, Register src, Register value,
                            RCBit r) {
  SubS64(dst, src, value, LeaveOE, r);
  extsw(dst, dst, r);
}

void MacroAssembler::SubS32(Register dst, Register src, const Operand& value,
                            Register scratch, RCBit r) {
  SubS64(dst, src, value, scratch, LeaveOE, r);
  extsw(dst, dst, r);
}

void MacroAssembler::MulS64(Register dst, Register src, const Operand& value,
                            Register scratch, OEBit s, RCBit r) {
  if (is_int16(value.immediate()) && s == LeaveOE && r == LeaveRC) {
    mulli(dst, src, value);
  } else {
    mov(scratch, value);
    mulld(dst, src, scratch, s, r);
  }
}

void MacroAssembler::MulS64(Register dst, Register src, Register value, OEBit s,
                            RCBit r) {
  mulld(dst, src, value, s, r);
}

void MacroAssembler::MulS32(Register dst, Register src, const Operand& value,
                            Register scratch, OEBit s, RCBit r) {
  MulS64(dst, src, value, scratch, s, r);
  extsw(dst, dst, r);
}

void MacroAssembler::MulS32(Register dst, Register src, Register value, OEBit s,
                            RCBit r) {
  MulS64(dst, src, value, s, r);
  extsw(dst, dst, r);
}

void MacroAssembler::DivS64(Register dst, Register src, Register value, OEBit s,
                            RCBit r) {
  divd(dst, src, value, s, r);
}

void MacroAssembler::DivU64(Register dst, Register src, Register value, OEBit s,
                            RCBit r) {
  divdu(dst, src, value, s, r);
}

void MacroAssembler::DivS32(Register dst, Register src, Register value, OEBit s,
                            RCBit r) {
  divw(dst, src, value, s, r);
  extsw(dst, dst);
}
void MacroAssembler::DivU32(Register dst, Register src, Register value, OEBit s,
                            RCBit r) {
  divwu(dst, src, value, s, r);
  ZeroExtWord32(dst, dst);
}

void MacroAssembler::ModS64(Register dst, Register src, Register value) {
  if (CpuFeatures::IsSupported(PPC_9_PLUS)) {
    modsd(dst, src, value);
  } else {
    Register scratch = GetRegisterThatIsNotOneOf(dst, src, value);
    Push(scratch);
    divd(scratch, src, value);
    mulld(scratch, scratch, value);
    sub(dst, src, scratch);
    Pop(scratch);
  }
}

void MacroAssembler::ModU64(Register dst, Register src, Register value) {
  if (CpuFeatures::IsSupported(PPC_9_PLUS)) {
    modud(dst, src, value);
  } else {
    Register scratch = GetRegisterThatIsNotOneOf(dst, src, value);
    Push(scratch);
    divdu(scratch, src, value);
    mulld(scratch, scratch, value);
    sub(dst, src, scratch);
    Pop(scratch);
  }
}

void MacroAssembler::ModS32(Register dst, Register src, Register value) {
  if (CpuFeatures::IsSupported(PPC_9_PLUS)) {
    modsw(dst, src, value);
  } else {
    Register scratch = GetRegisterThatIsNotOneOf(dst, src, value);
    Push(scratch);
    divw(scratch, src, value);
    mullw(scratch, scratch, value);
    sub(dst, src, scratch);
    Pop(scratch);
  }
  extsw(dst, dst);
}
void MacroAssembler::ModU32(Register dst, Register src, Register value) {
  if (CpuFeatures::IsSupported(PPC_9_PLUS)) {
    moduw(dst, src, value);
  } else {
    Register scratch = GetRegisterThatIsNotOneOf(dst, src, value);
    Push(scratch);
    divwu(scratch, src, value);
    mullw(scratch, scratch, value);
    sub(dst, src, scratch);
    Pop(scratch);
  }
  ZeroExtWord32(dst, dst);
}

void MacroAssembler::AndU64(Register dst, Register src, const Operand& value,
                            Register scratch, RCBit r) {
  if (is_uint16(value.immediate()) && r == SetRC) {
    andi(dst, src, value);
  } else {
    mov(scratch, value);
    and_(dst, src, scratch, r);
  }
}

void MacroAssembler::AndU64(Register dst, Register src, Register value,
                            RCBit r) {
  and_(dst, src, value, r);
}

void MacroAssembler::OrU64(Register dst, Register src, const Operand& value,
                           Register scratch, RCBit r) {
  if (is_int16(value.immediate()) && r == LeaveRC) {
    ori(dst, src, value);
  } else {
    mov(scratch, value);
    orx(dst, src, scratch, r);
  }
}

void MacroAssembler::OrU64(Register dst, Register src, Register value,
                           RCBit r) {
  orx(dst, src, value, r);
}

void MacroAssembler::XorU64(Register dst, Register src, const Operand& value,
                            Register scratch, RCBit r) {
  if (is_int16(value.immediate()) && r == LeaveRC) {
    xori(dst, src, value);
  } else {
    mov(scratch, value);
    xor_(dst, src, scratch, r);
  }
}

void MacroAssembler::XorU64(Register dst, Register src, Register value,
                            RCBit r) {
  xor_(dst, src, value, r);
}

void MacroAssembler::AndU32(Register dst, Register src, const Operand& value,
                            Register scratch, RCBit r) {
  AndU64(dst, src, value, scratch, r);
  extsw(dst, dst, r);
}

void MacroAssembler::AndU32(Register dst, Register src, Register value,
                            RCBit r) {
  AndU64(dst, src, value, r);
  extsw(dst, dst, r);
}

void MacroAssembler::OrU32(Register dst, Register src, const Operand& value,
                           Register scratch, RCBit r) {
  OrU64(dst, src, value, scratch, r);
  extsw(dst, dst, r);
}

void MacroAssembler::OrU32(Register dst, Register src, Register value,
                           RCBit r) {
  OrU64(dst, src, value, r);
  extsw(dst, dst, r);
}

void MacroAssembler::XorU32(Register dst, Register src, const Operand& value,
                            Register scratch, RCBit r) {
  XorU64(dst, src, value, scratch, r);
  extsw(dst, dst, r);
}

void MacroAssembler::XorU32(Register dst, Register src, Register value,
                            RCBit r) {
  XorU64(dst, src, value, r);
  extsw(dst, dst, r);
}

void MacroAssembler::ShiftLeftU64(Register dst, Register src,
                                  const Operand& value, RCBit r) {
  sldi(dst, src, value, r);
}

void MacroAssembler::ShiftRightU64(Register dst, Register src,
                                   const Operand& value, RCBit r) {
  srdi(dst, src, value, r);
}

void MacroAssembler::ShiftRightS64(Register dst, Register src,
                                   const Operand& value, RCBit r) {
  sradi(dst, src, value.immediate(), r);
}

void MacroAssembler::ShiftLeftU32(Register dst, Register src,
                                  const Operand& value, RCBit r) {
  slwi(dst, src, value, r);
}

void MacroAssembler::ShiftRightU32(Register dst, Register src,
                                   const Operand& value, RCBit r) {
  srwi(dst, src, value, r);
}

void MacroAssembler::ShiftRightS32(Register dst, Register src,
                                   const Operand& value, RCBit r) {
  srawi(dst, src, value.immediate(), r);
}

void MacroAssembler::ShiftLeftU64(Register dst, Register src, Register value,
                                  RCBit r) {
  sld(dst, src, value, r);
}

void MacroAssembler::ShiftRightU64(Register dst, Register src, Register value,
                                   RCBit r) {
  srd(dst, src, value, r);
}

void MacroAssembler::ShiftRightS64(Register dst, Register src, Register value,
                                   RCBit r) {
  srad(dst, src, value, r);
}

void MacroAssembler::ShiftLeftU32(Register dst, Register src, Register value,
                                  RCBit r) {
  slw(dst, src, value, r);
}

void MacroAssembler::ShiftRightU32(Register dst, Register src, Register value,
                                   RCBit r) {
  srw(dst, src, value, r);
}

void MacroAssembler::ShiftRightS32(Register dst, Register src, Register value,
                                   RCBit r) {
  sraw(dst, src, value, r);
}

void MacroAssembler::CmpS64(Register src1, Register src2, CRegister cr) {
  cmp(src1, src2, cr);
}

void MacroAssembler::CmpS64(Register src1, const Operand& src2,
                            Register scratch, CRegister cr) {
  intptr_t value = src2.immediate();
  if (is_int16(value)) {
    cmpi(src1, src2, cr);
  } else {
    mov(scratch, src2);
    CmpS64(src1, scratch, cr);
  }
}

void MacroAssembler::CmpU64(Register src1, const Operand& src2,
                            Register scratch, CRegister cr) {
  intptr_t value = src2.immediate();
  if (is_uint16(value)) {
    cmpli(src1, src2, cr);
  } else {
    mov(scratch, src2);
    CmpU64(src1, scratch, cr);
  }
}

void MacroAssembler::CmpU64(Register src1, Register src2, CRegister cr) {
  cmpl(src1, src2, cr);
}

void MacroAssembler::CmpS32(Register src1, const Operand& src2,
                            Register scratch, CRegister cr) {
  intptr_t value = src2.immediate();
  if (is_int16(value)) {
    cmpwi(src1, src2, cr);
  } else {
    mov(scratch, src2);
    CmpS32(src1, scratch, cr);
  }
}

void MacroAssembler::CmpS32(Register src1, Register src2, CRegister cr) {
  cmpw(src1, src2, cr);
}

void MacroAssembler::CmpU32(Register src1, const Operand& src2,
                            Register scratch, CRegister cr) {
  intptr_t value = src2.immediate();
  if (is_uint16(value)) {
    cmplwi(src1, src2, cr);
  } else {
    mov(scratch, src2);
    cmplw(src1, scratch, cr);
  }
}

void MacroAssembler::CmpU32(Register src1, Register src2, CRegister cr) {
  cmplw(src1, src2, cr);
}

void MacroAssembler::AddF64(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs, RCBit r) {
  fadd(dst, lhs, rhs, r);
}

void MacroAssembler::SubF64(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs, RCBit r) {
  fsub(dst, lhs, rhs, r);
}

void MacroAssembler::MulF64(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs, RCBit r) {
  fmul(dst, lhs, rhs, r);
}

void MacroAssembler::DivF64(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs, RCBit r) {
  fdiv(dst, lhs, rhs, r);
}

void MacroAssembler::AddF32(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs, RCBit r) {
  fadd(dst, lhs, rhs, r);
  frsp(dst, dst, r);
}

void MacroAssembler::SubF32(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs, RCBit r) {
  fsub(dst, lhs, rhs, r);
  frsp(dst, dst, r);
}

void MacroAssembler::MulF32(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs, RCBit r) {
  fmul(dst, lhs, rhs, r);
  frsp(dst, dst, r);
}

void MacroAssembler::DivF32(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs, RCBit r) {
  fdiv(dst, lhs, rhs, r);
  frsp(dst, dst, r);
}

void MacroAssembler::CopySignF64(DoubleRegister dst, DoubleRegister lhs,
                                 DoubleRegister rhs, RCBit r) {
  fcpsgn(dst, rhs, lhs, r);
}

void MacroAssembler::CmpSmiLiteral(Register src1, Tagged<Smi> smi,
                                   Register scratch, CRegister cr) {
#if defined(V8_COMPRESS_POINTERS) || defined(V8_31BIT_SMIS_ON_64BIT_ARCH)
  CmpS32(src1, Operand(smi), scratch, cr);
#else
  LoadSmiLiteral(scratch, smi);
  CmpS64(src1, scratch, cr);
#endif
}

void MacroAssembler::CmplSmiLiteral(Register src1, Tagged<Smi> smi,
                                    Register scratch, CRegister cr) {
#if defined(V8_COMPRESS_POINTERS) || defined(V8_31BIT_SMIS_ON_64BIT_ARCH)
  CmpU64(src1, Operand(smi), scratch, cr);
#else
  LoadSmiLiteral(scratch, smi);
  CmpU64(src1, scratch, cr);
#endif
}

void MacroAssembler::AddSmiLiteral(Register dst, Register src, Tagged<Smi> smi,
                                   Register scratch) {
#if defined(V8_COMPRESS_POINTERS) || defined(V8_31BIT_SMIS_ON_64BIT_ARCH)
  AddS64(dst, src, Operand(smi.ptr()), scratch);
#else
  LoadSmiLiteral(scratch, smi);
  add(dst, src, scratch);
#endif
}

void MacroAssembler::SubSmiLiteral(Register dst, Register src, Tagged<Smi> smi,
                                   Register scratch) {
#if defined(V8_COMPRESS_POINTERS) || defined(V8_31BIT_SMIS_ON_64BIT_ARCH)
  AddS64(dst, src, Operand(-(static_cast<intptr_t>(smi.ptr()))), scratch);
#else
  LoadSmiLiteral(scratch, smi);
  sub(dst, src, scratch);
#endif
}

void MacroAssembler::AndSmiLiteral(Register dst, Register src, Tagged<Smi> smi,
                                   Register scratch, RCBit rc) {
#if defined(V8_COMPRESS_POINTERS) || defined(V8_31BIT_SMIS_ON_64BIT_ARCH)
  AndU64(dst, src, Operand(smi), scratch, rc);
#else
  LoadSmiLiteral(scratch, smi);
  and_(dst, src, scratch, rc);
#endif
}

#define GenerateMemoryOperation(reg, mem, ri_op, rr_op) \
  {                                                     \
    int64_t offset = mem.offset();                      \
                                                        \
    if (mem.rb() == no_reg) {                           \
      if (!is_int16(offset)) {                          \
        /* cannot use d-form */                         \
        CHECK_NE(scratch, no_reg);                      \
        mov(scratch, Operand(offset));                  \
        rr_op(reg, MemOperand(mem.ra(), scratch));      \
      } else {                                          \
        ri_op(reg, mem);                                \
      }                                                 \
    } else {                                            \
      if (offset == 0) {                                \
        rr_op(reg, mem);                                \
      } else if (is_int16(offset)) {                    \
        CHECK_NE(scratch, no_reg);                      \
        addi(scratch, mem.rb(), Operand(offset));       \
        rr_op(reg, MemOperand(mem.ra(), scratch));      \
      } else {                                          \
        CHECK_NE(scratch, no_reg);                      \
        mov(scratch, Operand(offset));                  \
        add(scratch, scratch, mem.rb());                \
        rr_op(reg, MemOperand(mem.ra(), scratch));      \
      }                                                 \
    }                                                   \
  }

#define GenerateMemoryOperationRR(reg, mem, op)                \
  {                                                            \
    if (mem.offset() == 0) {                                   \
      if (mem.rb() != no_reg)                                  \
        op(reg, mem);                                          \
      else                                                     \
        op(reg, MemOperand(r0, mem.ra()));                     \
    } else if (is_int16(mem.offset())) {                       \
      if (mem.rb() != no_reg)                                  \
        addi(scratch, mem.rb(), Operand(mem.offset()));        \
      else                                                     \
        mov(scratch, Operand(mem.offset()));                   \
      op(reg, MemOperand(mem.ra(), scratch));                  \
    } else {                                                   \
      mov(scratch, Operand(mem.offset()));                     \
      if (mem.rb() != no_reg) add(scratch, scratch, mem.rb()); \
      op(reg, MemOperand(mem.ra(), scratch));                  \
    }                                                          \
  }

#define GenerateMemoryOperationPrefixed(reg, mem, ri_op, rip_op, rr_op)       \
  {                                                                           \
    int64_t offset = mem.offset();                                            \
                                                                              \
    if (mem.rb() == no_reg) {                                                 \
      if (is_int16(offset)) {                                                 \
        ri_op(reg, mem);                                                      \
      } else if (is_int34(offset) && CpuFeatures::IsSupported(PPC_10_PLUS)) { \
        rip_op(reg, mem);                                                     \
      } else {                                                                \
        /* cannot use d-form */                                               \
        CHECK_NE(scratch, no_reg);                                            \
        mov(scratch, Operand(offset));                                        \
        rr_op(reg, MemOperand(mem.ra(), scratch));                            \
      }                                                                       \
    } else {                                                                  \
      if (offset == 0) {                                                      \
        rr_op(reg, mem);                                                      \
      } else if (is_int16(offset)) {                                          \
        CHECK_NE(scratch, no_reg);                                            \
        addi(scratch, mem.rb(), Operand(offset));                             \
        rr_op(reg, MemOperand(mem.ra(), scratch));                            \
      } else {                                                                \
        CHECK_NE(scratch, no_reg);                                            \
        mov(scratch, Operand(offset));                                        \
        add(scratch, scratch, mem.rb());                                      \
        rr_op(reg, MemOperand(mem.ra(), scratch));                            \
      }                                                                       \
    }                                                                         \
  }

#define GenerateMemoryOperationWithAlign(reg, mem, ri_op, rr_op) \
  {                                                              \
    int64_t offset = mem.offset();                               \
    int misaligned = (offset & 3);                               \
                                                                 \
    if (mem.rb() == no_reg) {                                    \
      if (!is_int16(offset) || misaligned) {                     \
        /* cannot use d-form */                                  \
        CHECK_NE(scratch, no_reg);                               \
        mov(scratch, Operand(offset));                           \
        rr_op(reg, MemOperand(mem.ra(), scratch));               \
      } else {                                                   \
        ri_op(reg, mem);                                         \
      }                                                          \
    } else {                                                     \
      if (offset == 0) {                                         \
        rr_op(reg, mem);                                         \
      } else if (is_int16(offset)) {                             \
        CHECK_NE(scratch, no_reg);                               \
        addi(scratch, mem.rb(), Operand(offset));                \
        rr_op(reg, MemOperand(mem.ra(), scratch));               \
      } else {                                                   \
        CHECK_NE(scratch, no_reg);                               \
        mov(scratch, Operand(offset));                           \
        add(scratch, scratch, mem.rb());                         \
        rr_op(reg, MemOperand(mem.ra(), scratch));               \
      }                                                          \
    }                                                            \
  }

#define GenerateMemoryOperationWithAlignPrefixed(reg, mem, ri_op, rip_op,     \
                                                 rr_op)                       \
  {                                                                           \
    int64_t offset = mem.offset();                                            \
    int misaligned = (offset & 3);                                            \
                                                                              \
    if (mem.rb() == no_reg) {                                                 \
      if (is_int16(offset) && !misaligned) {                                  \
        ri_op(reg, mem);                                                      \
      } else if (is_int34(offset) && CpuFeatures::IsSupported(PPC_10_PLUS)) { \
        rip_op(reg, mem);                                                     \
      } else {                                                                \
        /* cannot use d-form */                                               \
        CHECK_NE(scratch, no_reg);                                            \
        mov(scratch, Operand(offset));                                        \
        rr_op(reg, MemOperand(mem.ra(), scratch));                            \
      }                                                                       \
    } else {                                                                  \
      if (offset == 0) {                                                      \
        rr_op(reg, mem);                                                      \
      } else if (is_int16(offset)) {                                          \
        CHECK_NE(scratch, no_reg);                                            \
        addi(scratch, mem.rb(), Operand(offset));                             \
        rr_op(reg, MemOperand(mem.ra(), scratch));                            \
      } else {                                                                \
        CHECK_NE(scratch, no_reg);                                            \
        mov(scratch, Operand(offset));                                        \
        add(scratch, scratch, mem.rb());                                      \
        rr_op(reg, MemOperand(mem.ra(), scratch));                            \
      }                                                                       \
    }                                                                         \
  }

#define MEM_OP_WITH_ALIGN_LIST(V) \
  V(LoadU64WithUpdate, ldu, ldux) \
  V(StoreU64WithUpdate, stdu, stdux)

#define MEM_OP_WITH_ALIGN_FUNCTION(name, ri_op, rr_op)           \
  void MacroAssembler::name(Register reg, const MemOperand& mem, \
                            Register scratch) {                  \
    GenerateMemoryOperationWithAlign(reg, mem, ri_op, rr_op);    \
  }
MEM_OP_WITH_ALIGN_LIST(MEM_OP_WITH_ALIGN_FUNCTION)
#undef MEM_OP_WITH_ALIGN_LIST
#undef MEM_OP_WITH_ALIGN_FUNCTION

#define MEM_OP_WITH_ALIGN_PREFIXED_LIST(V) \
  V(LoadS32, lwa, plwa, lwax)              \
  V(LoadU64, ld, pld, ldx)                 \
  V(StoreU64, std, pstd, stdx)

#define MEM_OP_WITH_ALIGN_PREFIXED_FUNCTION(name, ri_op, rip_op, rr_op)       \
  void MacroAssembler::name(Register reg, const MemOperand& mem,              \
                            Register scratch) {                               \
    GenerateMemoryOperationWithAlignPrefixed(reg, mem, ri_op, rip_op, rr_op); \
  }
MEM_OP_WITH_ALIGN_PREFIXED_LIST(MEM_OP_WITH_ALIGN_PREFIXED_FUNCTION)
#undef MEM_OP_WITH_ALIGN_PREFIXED_LIST
#undef MEM_OP_WITH_ALIGN_PREFIXED_FUNCTION

#define MEM_OP_LIST(V)                                 \
  V(LoadF64WithUpdate, DoubleRegister, lfdu, lfdux)    \
  V(LoadF32WithUpdate, DoubleRegister, lfsu, lfsux)    \
  V(StoreF64WithUpdate, DoubleRegister, stfdu, stfdux) \
  V(StoreF32WithUpdate, DoubleRegister, stfsu, stfsux)

#define MEM_OP_FUNCTION(name, result_t, ri_op, rr_op)            \
  void MacroAssembler::name(result_t reg, const MemOperand& mem, \
                            Register scratch) {                  \
    GenerateMemoryOperation(reg, mem, ri_op, rr_op);             \
  }
MEM_OP_LIST(MEM_OP_FUNCTION)
#undef MEM_OP_LIST
#undef MEM_OP_FUNCTION

#define MEM_OP_PREFIXED_LIST(V)                   \
  V(LoadU32, Register, lwz, plwz, lwzx)           \
  V(LoadS16, Register, lha, plha, lhax)           \
  V(LoadU16, Register, lhz, plhz, lhzx)           \
  V(LoadU8, Register, lbz, plbz, lbzx)            \
  V(StoreU32, Register, stw, pstw, stwx)          \
  V(StoreU16, Register, sth, psth, sthx)          \
  V(StoreU8, Register, stb, pstb, stbx)           \
  V(LoadF64, DoubleRegister, lfd, plfd, lfdx)     \
  V(LoadF32, DoubleRegister, lfs, plfs, lfsx)     \
  V(StoreF64, DoubleRegister, stfd, pstfd, stfdx) \
  V(StoreF32, DoubleRegister, stfs, pstfs, stfsx)

#define MEM_OP_PREFIXED_FUNCTION(name, result_t, ri_op, rip_op, rr_op) \
  void MacroAssembler::name(result_t reg, const MemOperand& mem,       \
                            Register scratch) {                        \
    GenerateMemoryOperationPrefixed(reg, mem, ri_op, rip_op, rr_op);   \
  }
MEM_OP_PREFIXED_LIST(MEM_OP_PREFIXED_FUNCTION)
#undef MEM_OP_PREFIXED_LIST
#undef MEM_OP_PREFIXED_FUNCTION

#define MEM_OP_SIMD_LIST(V)      \
  V(LoadSimd128, lxvx)           \
  V(StoreSimd128, stxvx)         \
  V(LoadSimd128Uint64, lxsdx)    \
  V(LoadSimd128Uint32, lxsiwzx)  \
  V(LoadSimd128Uint16, lxsihzx)  \
  V(LoadSimd128Uint8, lxsibzx)   \
  V(StoreSimd128Uint64, stxsdx)  \
  V(StoreSimd128Uint32, stxsiwx) \
  V(StoreSimd128Uint16, stxsihx) \
  V(StoreSimd128Uint8, stxsibx)

#define MEM_OP_SIMD_FUNCTION(name, rr_op)                               \
  void MacroAssembler::name(Simd128Register reg, const MemOperand& mem, \
                            Register scratch) {                         \
    GenerateMemoryOperationRR(reg, mem, rr_op);                         \
  }
MEM_OP_SIMD_LIST(MEM_OP_SIMD_FUNCTION)
#undef MEM_OP_SIMD_LIST
#undef MEM_OP_SIMD_FUNCTION

void MacroAssembler::LoadS8(Register dst, const MemOperand& mem,
                            Register scratch) {
  LoadU8(dst, mem, scratch);
  extsb(dst, dst);
}

#define MEM_LE_OP_LIST(V) \
  V(LoadU64, ldbrx)       \
  V(LoadU32, lwbrx)       \
  V(LoadU16, lhbrx)       \
  V(StoreU64, stdbrx)     \
  V(StoreU32, stwbrx)     \
  V(StoreU16, sthbrx)

#ifdef V8_TARGET_BIG_ENDIAN
#define MEM_LE_OP_FUNCTION(name, op)                                 \
  void MacroAssembler::name##LE(Register reg, const MemOperand& mem, \
                                Register scratch) {                  \
    GenerateMemoryOperationRR(reg, mem, op);                         \
  }
#else
#define MEM_LE_OP_FUNCTION(name, op)                                 \
  void MacroAssembler::name##LE(Register reg, const MemOperand& mem, \
                                Register scratch) {                  \
    name(reg, mem, scratch);                                         \
  }
#endif

MEM_LE_OP_LIST(MEM_LE_OP_FUNCTION)
#undef MEM_LE_OP_FUNCTION
#undef MEM_LE_OP_LIST

void MacroAssembler::LoadS32LE(Register dst, const MemOperand& mem,
                               Register scratch) {
#ifdef V8_TARGET_BIG_ENDIAN
  LoadU32LE(dst, mem, scratch);
  extsw(dst, dst);
#else
  LoadS32(dst, mem, scratch);
#endif
}

void MacroAssembler::LoadS16LE(Register dst, const MemOperand& mem,
```