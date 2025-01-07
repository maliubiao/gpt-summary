Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/codegen/s390/macro-assembler-s390.cc`.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Purpose:** The file name `macro-assembler-s390.cc` strongly suggests that this code is responsible for generating machine code instructions for the s390 architecture. It's a low-level component of the V8 JavaScript engine.

2. **Analyze the Code Structure:**  The code is filled with C++ functions (methods of the `MacroAssembler` class). Many of these functions have names that clearly indicate their purpose, such as `DivS64`, `AddS32`, `CmpS32`, `LoadU64`, etc. These names hint at the specific machine instructions they encapsulate.

3. **Group Functionalities:**  The code is logically organized into sections based on the type of operations:
    * Division (signed and unsigned, 32-bit and 64-bit)
    * Modulo (signed and unsigned, 32-bit and 64-bit)
    * Multiplication (signed 64-bit, high bits of multiplication)
    * Addition (signed and unsigned, immediate, register, memory operands)
    * Subtraction (signed and unsigned, immediate, register, memory operands)
    * Bitwise operations (AND, OR, XOR, NOT)
    * Comparisons (signed and unsigned, immediate, register, memory operands, floating-point)
    * Branching
    * Loading and storing data (various sizes, including SMI literals)
    * Atomic operations (Compare and Swap)

4. **Infer Function Implementations:**  The code uses macros like `Generate_Div64` to abstract away some of the instruction sequences. Even without knowing the exact implementation of these macros, the surrounding code gives clues. For example, the `DivS64` function loads values into registers `r0` and `r1`, calls an `instr` macro, and then moves the result. This pattern is common in assembly language for performing arithmetic operations.

5. **Address Specific User Questions:**
    * **`.tq` extension:**  The user correctly identified that a `.tq` extension indicates Torque code. This file does not have that extension, so it's not Torque.
    * **Relationship to JavaScript:**  MacroAssembler code is directly responsible for implementing JavaScript operations at the machine code level. Think of arithmetic, logical operations, data access, and control flow in JavaScript – these need to be translated into assembly instructions. An example of `a + b` in JavaScript translates to an `AddS64` or `AddS32` call in this C++ code (after type checking and other higher-level processing).
    * **Code Logic Inference:** For operations like division and modulo, the code loads the operands into specific registers (`r0`, `r1`) and uses dedicated instructions. The assumption is that these instructions perform the intended operation on those registers. Input: two registers with numbers. Output: the result of the operation in a designated register.
    * **Common Programming Errors:**  Since this code is at a very low level, it doesn't directly deal with typical high-level JavaScript errors. However, a common error *in the context of using an assembler* would be incorrect register usage or memory addressing.
    * **Overall Functionality:** Synthesize the findings from the previous steps into a concise summary.

6. **Structure the Answer:** Present the information in a clear and organized manner, using bullet points or numbered lists for different functionalities. Address each of the user's specific questions.

7. **Review and Refine:** Ensure the answer is accurate, comprehensive, and easy to understand. For instance, initially, I might just list the function names. However, providing a higher-level categorization (arithmetic, logical, memory access, etc.) makes the answer more helpful. Also, explicitly stating the connection to JavaScript with an example strengthens the explanation. Similarly, elaborating on the kind of programming errors relevant to assembly programming is more informative than just saying "programming errors."
`v8/src/codegen/s390/macro-assembler-s390.cc` 是 V8 JavaScript 引擎中针对 s390 架构的宏汇编器源代码文件。它的主要功能是提供一组高级接口（C++ 函数）来生成底层的 s390 汇编指令序列。这使得 V8 的代码生成器能够更容易地产生高效的目标机器代码。

以下是该文件列举的功能的归纳：

* **算术运算指令生成:**  提供了生成 s390 架构下各种算术运算指令的函数，包括：
    * **加法 (Add):**  支持 32 位和 64 位有符号和无符号整数的加法，包括寄存器与寄存器、寄存器与立即数、寄存器与内存的操作数形式。
    * **减法 (Sub):** 支持 32 位和 64 位有符号和无符号整数的减法，包括寄存器与寄存器、寄存器与立即数、寄存器与内存的操作数形式。
    * **乘法 (Mul):**  支持 64 位有符号整数的乘法，以及获取 64 位乘法结果高位的操作。
    * **除法 (Div):**  支持 32 位和 64 位有符号和无符号整数的除法。
    * **取模 (Mod):**  支持 32 位和 64 位有符号和无符号整数的取模运算。
    * **平方根 (Sqrt):** 支持浮点数的平方根运算。

* **位运算指令生成:** 提供了生成 s390 架构下各种位运算指令的函数，包括：
    * **与 (And):** 支持 32 位和 64 位整数的按位与操作，包括寄存器与寄存器、寄存器与立即数、寄存器与内存的操作数形式。
    * **或 (Or):** 支持 32 位和 64 位整数的按位或操作，包括寄存器与寄存器、寄存器与立即数、寄存器与内存的操作数形式。
    * **异或 (Xor):** 支持 32 位和 64 位整数的按位异或操作，包括寄存器与寄存器、寄存器与立即数、寄存器与内存的操作数形式。
    * **非 (Not):** 支持 32 位和 64 位整数的按位取反操作。

* **比较指令生成:** 提供了生成 s390 架构下各种比较指令的函数，包括：
    * **整数比较 (CmpS32, CmpS64, CmpU32, CmpU64):**  支持 32 位和 64 位有符号和无符号整数的比较，包括寄存器与寄存器、寄存器与立即数、寄存器与内存的操作数形式。
    * **浮点数比较 (CmpF32, CmpF64):** 支持单精度和双精度浮点数的比较。
    * **比较并交换 (CmpAndSwap, CmpAndSwap64):**  用于实现原子操作。

* **数据加载和存储指令生成:** 提供了生成 s390 架构下各种数据加载和存储指令的函数，包括：
    * **加载 (Load):**  支持加载 8 位、16 位、32 位和 64 位数据，并可以进行符号扩展或零扩展。
    * **存储 (Store):** 支持存储 32 位和 64 位数据。
    * **加载多个寄存器 (LoadMultipleP, LoadMultipleW):**  一次性加载多个寄存器的值。
    * **存储多个寄存器 (StoreMultipleP, StoreMultipleW):** 一次性存储多个寄存器的值。
    * **加载 SMI 字面量 (LoadSmiLiteral):**  加载 Small Integer 字面量。

* **分支指令生成:**  提供了生成 s390 架构下分支指令的函数，允许基于条件码跳转到指定的地址。

* **类型转换指令生成:** 提供了在整数和浮点数之间进行类型转换的指令。

* **其他实用指令:**  例如加载正数 (LoadPositiveP, LoadPositive32)。

**如果 `v8/src/codegen/s390/macro-assembler-s390.cc` 以 `.tq` 结尾，那它是个 v8 torque 源代码。**  但根据提供的文件路径和内容，它是一个 C++ 文件，而不是 Torque 文件。 Torque 是一种用于生成高效机器代码的 V8 内部领域特定语言。

**它与 javascript 的功能有关系，请用 javascript 举例说明:**

`macro-assembler-s390.cc` 中的代码直接负责将 JavaScript 的高级操作转化为底层的机器指令。例如，当你在 JavaScript 中执行一个加法运算时，V8 的代码生成器最终会调用 `MacroAssembler::AddS64` 或 `MacroAssembler::AddS32` (取决于操作数的类型) 来生成相应的 s390 加法指令。

```javascript
// JavaScript 代码示例
let a = 10;
let b = 5;
let sum = a + b;
```

在 V8 的执行过程中，当执行到 `a + b` 时，代码生成器可能会生成类似于以下的汇编指令（使用 `MacroAssembler` 中的函数）：

```assembly
// 假设 a 和 b 的值分别在寄存器 r2 和 r3 中
agr r1, r2, r3  // 将 r2 和 r3 的值相加，结果存储在 r1 中
// 然后可能将 r1 的值存储到变量 sum 对应的内存位置
```

`MacroAssembler::AddS64(r1, r2, r3)` 这个 C++ 函数就是用来生成 `agr r1, r2, r3` 这条 s390 汇编指令的。

**如果有代码逻辑推理，请给出假设输入与输出:**

考虑 `MacroAssembler::AddS64(Register dst, Register src1, Register src2)` 函数。

**假设输入:**
* `dst`: 寄存器 `r1`
* `src1`: 寄存器 `r2`，其值为 10 (0xA)
* `src2`: 寄存器 `r3`，其值为 5 (0x5)

**输出:**
该函数会生成一条 `agr r1, r2, r3` 的汇编指令。当这条指令被 CPU 执行后，寄存器 `r1` 的值将会变成 15 (0xF)。

**如果涉及用户常见的编程错误，请举例说明:**

`macro-assembler-s390.cc` 本身是 V8 引擎的内部代码，普通 JavaScript 开发者不会直接接触到它。然而，这个文件实现的功能与一些常见的编程错误间接相关。 例如：

* **整数溢出:** 如果 JavaScript 代码执行的整数运算超出了 s390 架构整数类型的表示范围，可能会导致溢出。虽然 `MacroAssembler` 提供了有符号和无符号的加减法，但它并不会自动进行溢出检查。

  ```javascript
  // JavaScript 代码
  let maxInt = Number.MAX_SAFE_INTEGER;
  let result = maxInt + 1;
  console.log(result === maxInt + 1); // 输出 false，因为发生了溢出
  ```

  在底层，`MacroAssembler::AddS64` 可能会被调用，但由于 s390 的加法指令本身不抛出异常，溢出行为可能会导致意想不到的结果。

* **类型错误:**  JavaScript 是一种动态类型语言，如果对类型不匹配的操作数进行运算，可能会导致错误。 V8 的代码生成器需要根据操作数的实际类型选择合适的 `MacroAssembler` 函数。

  ```javascript
  // JavaScript 代码
  let a = 10;
  let b = "5";
  let sum = a + b; // JavaScript 会进行类型转换，结果是字符串 "105"
  ```

  在这种情况下，V8 不会直接调用整数加法的 `MacroAssembler::AddSxx` 函数，而是会调用处理字符串连接或类型转换的相关代码。

**这是第4部分，共8部分，请归纳一下它的功能:**

基于以上分析，`v8/src/codegen/s390/macro-assembler-s390.cc` 的主要功能是：

**作为 V8 JavaScript 引擎中针对 s390 架构的代码生成器的基础构建块，它提供了一组 C++ 接口，用于生成各种 s390 汇编指令，涵盖算术运算、位运算、比较、数据加载和存储、分支以及类型转换等核心操作。 这使得 V8 能够将 JavaScript 代码高效地编译成可在 s390 架构上执行的机器代码。**

Prompt: 
```
这是目录为v8/src/codegen/s390/macro-assembler-s390.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/s390/macro-assembler-s390.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共8部分，请归纳一下它的功能

"""
                    \
    lgr(r1, src1);            \
    instr(r0, src2);          \
    lgr(dst, r1);             \
  }

void MacroAssembler::DivS64(Register dst, Register src1,
                            const MemOperand& src2) {
  Generate_Div64(dsg);
}

void MacroAssembler::DivS64(Register dst, Register src1, Register src2) {
  Generate_Div64(dsgr);
}

#undef Generate_Div64

#define Generate_DivU64(instr) \
  {                            \
    lgr(r1, src1);             \
    lghi(r0, Operand::Zero()); \
    instr(r0, src2);           \
    lgr(dst, r1);              \
  }

void MacroAssembler::DivU64(Register dst, Register src1,
                            const MemOperand& src2) {
  Generate_DivU64(dlg);
}

void MacroAssembler::DivU64(Register dst, Register src1, Register src2) {
  Generate_DivU64(dlgr);
}

#undef Generate_DivU64

#define Generate_Mod32(instr) \
  {                           \
    lgfr(r1, src1);           \
    instr(r0, src2);          \
    LoadU32(dst, r0);         \
  }

void MacroAssembler::ModS32(Register dst, Register src1,
                            const MemOperand& src2) {
  Generate_Mod32(dsgf);
}

void MacroAssembler::ModS32(Register dst, Register src1, Register src2) {
  Generate_Mod32(dsgfr);
}

#undef Generate_Mod32

#define Generate_ModU32(instr) \
  {                            \
    lr(r0, src1);              \
    srdl(r0, Operand(32));     \
    instr(r0, src2);           \
    LoadU32(dst, r0);          \
  }

void MacroAssembler::ModU32(Register dst, Register src1,
                            const MemOperand& src2) {
  Generate_ModU32(dl);
}

void MacroAssembler::ModU32(Register dst, Register src1, Register src2) {
  Generate_ModU32(dlr);
}

#undef Generate_ModU32

#define Generate_Mod64(instr) \
  {                           \
    lgr(r1, src1);            \
    instr(r0, src2);          \
    lgr(dst, r0);             \
  }

void MacroAssembler::ModS64(Register dst, Register src1,
                            const MemOperand& src2) {
  Generate_Mod64(dsg);
}

void MacroAssembler::ModS64(Register dst, Register src1, Register src2) {
  Generate_Mod64(dsgr);
}

#undef Generate_Mod64

#define Generate_ModU64(instr) \
  {                            \
    lgr(r1, src1);             \
    lghi(r0, Operand::Zero()); \
    instr(r0, src2);           \
    lgr(dst, r0);              \
  }

void MacroAssembler::ModU64(Register dst, Register src1,
                            const MemOperand& src2) {
  Generate_ModU64(dlg);
}

void MacroAssembler::ModU64(Register dst, Register src1, Register src2) {
  Generate_ModU64(dlgr);
}

#undef Generate_ModU64

void MacroAssembler::MulS64(Register dst, const Operand& opnd) {
  msgfi(dst, opnd);
}

void MacroAssembler::MulS64(Register dst, Register src) { msgr(dst, src); }

void MacroAssembler::MulS64(Register dst, const MemOperand& opnd) {
  msg(dst, opnd);
}

void MacroAssembler::MulHighS64(Register dst, Register src1, Register src2) {
  if (CpuFeatures::IsSupported(MISC_INSTR_EXT2)) {
    mgrk(r0, src1, src2);
    lgr(dst, r0);
  } else {
    SaveFPRegsMode fp_mode = SaveFPRegsMode::kSave;
    PushCallerSaved(fp_mode, ip);
    Push(src1, src2);
    Pop(r2, r3);
    {
      FrameScope scope(this, StackFrame::INTERNAL);
      PrepareCallCFunction(2, 0, r0);
      CallCFunction(ExternalReference::int64_mul_high_function(), 2, 0);
    }
    mov(r0, r2);
    PopCallerSaved(fp_mode, ip);
    mov(dst, r0);
  }
}

void MacroAssembler::MulHighS64(Register dst, Register src1,
                                const MemOperand& src2) {
  // TODO(v8): implement this.
  UNIMPLEMENTED();
}

void MacroAssembler::MulHighU64(Register dst, Register src1, Register src2) {
  lgr(r1, src1);
  mlgr(r0, src2);
  lgr(dst, r0);
}

void MacroAssembler::MulHighU64(Register dst, Register src1,
                                const MemOperand& src2) {
  // TODO(v8): implement this.
  UNIMPLEMENTED();
}

void MacroAssembler::Sqrt(DoubleRegister result, DoubleRegister input) {
  sqdbr(result, input);
}
void MacroAssembler::Sqrt(DoubleRegister result, const MemOperand& input) {
  if (is_uint12(input.offset())) {
    sqdb(result, input);
  } else {
    ldy(result, input);
    sqdbr(result, result);
  }
}
//----------------------------------------------------------------------------
//  Add Instructions
//----------------------------------------------------------------------------

// Add 32-bit (Register dst = Register dst + Immediate opnd)
void MacroAssembler::AddS32(Register dst, const Operand& opnd) {
  if (is_int16(opnd.immediate()))
    ahi(dst, opnd);
  else
    afi(dst, opnd);
}

// Add Pointer Size (Register dst = Register dst + Immediate opnd)
void MacroAssembler::AddS64(Register dst, const Operand& opnd) {
  if (is_int16(opnd.immediate()))
    aghi(dst, opnd);
  else
    agfi(dst, opnd);
}

void MacroAssembler::AddS32(Register dst, Register src, int32_t opnd) {
  AddS32(dst, src, Operand(opnd));
}

// Add 32-bit (Register dst = Register src + Immediate opnd)
void MacroAssembler::AddS32(Register dst, Register src, const Operand& opnd) {
  if (dst != src) {
    if (CpuFeatures::IsSupported(DISTINCT_OPS) && is_int16(opnd.immediate())) {
      ahik(dst, src, opnd);
      return;
    }
    lr(dst, src);
  }
  AddS32(dst, opnd);
}

void MacroAssembler::AddS64(Register dst, Register src, int32_t opnd) {
  AddS64(dst, src, Operand(opnd));
}

// Add Pointer Size (Register dst = Register src + Immediate opnd)
void MacroAssembler::AddS64(Register dst, Register src, const Operand& opnd) {
  if (dst != src) {
    if (CpuFeatures::IsSupported(DISTINCT_OPS) && is_int16(opnd.immediate())) {
      aghik(dst, src, opnd);
      return;
    }
    mov(dst, src);
  }
  AddS64(dst, opnd);
}

// Add 32-bit (Register dst = Register dst + Register src)
void MacroAssembler::AddS32(Register dst, Register src) { ar(dst, src); }

// Add Pointer Size (Register dst = Register dst + Register src)
void MacroAssembler::AddS64(Register dst, Register src) { agr(dst, src); }

// Add 32-bit (Register dst = Register src1 + Register src2)
void MacroAssembler::AddS32(Register dst, Register src1, Register src2) {
  if (dst != src1 && dst != src2) {
    // We prefer to generate AR/AGR, over the non clobbering ARK/AGRK
    // as AR is a smaller instruction
    if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
      ark(dst, src1, src2);
      return;
    } else {
      lr(dst, src1);
    }
  } else if (dst == src2) {
    src2 = src1;
  }
  ar(dst, src2);
}

// Add Pointer Size (Register dst = Register src1 + Register src2)
void MacroAssembler::AddS64(Register dst, Register src1, Register src2) {
  if (dst != src1 && dst != src2) {
    // We prefer to generate AR/AGR, over the non clobbering ARK/AGRK
    // as AR is a smaller instruction
    if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
      agrk(dst, src1, src2);
      return;
    } else {
      mov(dst, src1);
    }
  } else if (dst == src2) {
    src2 = src1;
  }
  agr(dst, src2);
}

// Add 32-bit (Register-Memory)
void MacroAssembler::AddS32(Register dst, const MemOperand& opnd) {
  DCHECK(is_int20(opnd.offset()));
  if (is_uint12(opnd.offset()))
    a(dst, opnd);
  else
    ay(dst, opnd);
}

// Add Pointer Size (Register-Memory)
void MacroAssembler::AddS64(Register dst, const MemOperand& opnd) {
  DCHECK(is_int20(opnd.offset()));
  ag(dst, opnd);
}

// Add 32-bit (Memory - Immediate)
void MacroAssembler::AddS32(const MemOperand& opnd, const Operand& imm) {
  DCHECK(is_int8(imm.immediate()));
  DCHECK(is_int20(opnd.offset()));
  DCHECK(CpuFeatures::IsSupported(GENERAL_INSTR_EXT));
  asi(opnd, imm);
}

// Add Pointer-sized (Memory - Immediate)
void MacroAssembler::AddS64(const MemOperand& opnd, const Operand& imm) {
  DCHECK(is_int8(imm.immediate()));
  DCHECK(is_int20(opnd.offset()));
  DCHECK(CpuFeatures::IsSupported(GENERAL_INSTR_EXT));
  agsi(opnd, imm);
}

//----------------------------------------------------------------------------
//  Add Logical Instructions
//----------------------------------------------------------------------------

// Add Logical 32-bit (Register dst = Register src1 + Register src2)
void MacroAssembler::AddU32(Register dst, Register src1, Register src2) {
  if (dst != src2 && dst != src1) {
    lr(dst, src1);
    alr(dst, src2);
  } else if (dst != src2) {
    // dst == src1
    DCHECK(dst == src1);
    alr(dst, src2);
  } else {
    // dst == src2
    DCHECK(dst == src2);
    alr(dst, src1);
  }
}

// Add Logical 32-bit (Register dst = Register dst + Immediate opnd)
void MacroAssembler::AddU32(Register dst, const Operand& imm) {
  alfi(dst, imm);
}

// Add Logical Pointer Size (Register dst = Register dst + Immediate opnd)
void MacroAssembler::AddU64(Register dst, const Operand& imm) {
  algfi(dst, imm);
}

void MacroAssembler::AddU64(Register dst, Register src1, Register src2) {
  if (dst != src2 && dst != src1) {
    if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
      algrk(dst, src1, src2);
    } else {
      lgr(dst, src1);
      algr(dst, src2);
    }
  } else if (dst != src2) {
    // dst == src1
    DCHECK(dst == src1);
    algr(dst, src2);
  } else {
    // dst == src2
    DCHECK(dst == src2);
    algr(dst, src1);
  }
}

// Add Logical 32-bit (Register-Memory)
void MacroAssembler::AddU32(Register dst, const MemOperand& opnd) {
  DCHECK(is_int20(opnd.offset()));
  if (is_uint12(opnd.offset()))
    al_z(dst, opnd);
  else
    aly(dst, opnd);
}

// Add Logical Pointer Size (Register-Memory)
void MacroAssembler::AddU64(Register dst, const MemOperand& opnd) {
  DCHECK(is_int20(opnd.offset()));
  alg(dst, opnd);
}

//----------------------------------------------------------------------------
//  Subtract Instructions
//----------------------------------------------------------------------------

// Subtract Logical 32-bit (Register dst = Register src1 - Register src2)
void MacroAssembler::SubU32(Register dst, Register src1, Register src2) {
  if (dst != src2 && dst != src1) {
    lr(dst, src1);
    slr(dst, src2);
  } else if (dst != src2) {
    // dst == src1
    DCHECK(dst == src1);
    slr(dst, src2);
  } else {
    // dst == src2
    DCHECK(dst == src2);
    lr(r0, dst);
    SubU32(dst, src1, r0);
  }
}

// Subtract 32-bit (Register dst = Register dst - Immediate opnd)
void MacroAssembler::SubS32(Register dst, const Operand& imm) {
  AddS32(dst, Operand(-(imm.immediate())));
}

// Subtract Pointer Size (Register dst = Register dst - Immediate opnd)
void MacroAssembler::SubS64(Register dst, const Operand& imm) {
  AddS64(dst, Operand(-(imm.immediate())));
}

void MacroAssembler::SubS32(Register dst, Register src, int32_t imm) {
  SubS32(dst, src, Operand(imm));
}

// Subtract 32-bit (Register dst = Register src - Immediate opnd)
void MacroAssembler::SubS32(Register dst, Register src, const Operand& imm) {
  AddS32(dst, src, Operand(-(imm.immediate())));
}

void MacroAssembler::SubS64(Register dst, Register src, int32_t imm) {
  SubS64(dst, src, Operand(imm));
}

// Subtract Pointer Sized (Register dst = Register src - Immediate opnd)
void MacroAssembler::SubS64(Register dst, Register src, const Operand& imm) {
  AddS64(dst, src, Operand(-(imm.immediate())));
}

// Subtract 32-bit (Register dst = Register dst - Register src)
void MacroAssembler::SubS32(Register dst, Register src) { sr(dst, src); }

// Subtract Pointer Size (Register dst = Register dst - Register src)
void MacroAssembler::SubS64(Register dst, Register src) { sgr(dst, src); }

// Subtract 32-bit (Register = Register - Register)
void MacroAssembler::SubS32(Register dst, Register src1, Register src2) {
  // Use non-clobbering version if possible
  if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
    srk(dst, src1, src2);
    return;
  }
  if (dst != src1 && dst != src2) lr(dst, src1);
  // In scenario where we have dst = src - dst, we need to swap and negate
  if (dst != src1 && dst == src2) {
    Label done;
    lcr(dst, dst);  // dst = -dst
    b(overflow, &done);
    ar(dst, src1);  // dst = dst + src
    bind(&done);
  } else {
    sr(dst, src2);
  }
}

// Subtract Pointer Sized (Register = Register - Register)
void MacroAssembler::SubS64(Register dst, Register src1, Register src2) {
  // Use non-clobbering version if possible
  if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
    sgrk(dst, src1, src2);
    return;
  }
  if (dst != src1 && dst != src2) mov(dst, src1);
  // In scenario where we have dst = src - dst, we need to swap and negate
  if (dst != src1 && dst == src2) {
    Label done;
    lcgr(dst, dst);  // dst = -dst
    b(overflow, &done);
    AddS64(dst, src1);  // dst = dst + src
    bind(&done);
  } else {
    SubS64(dst, src2);
  }
}

// Subtract 32-bit (Register-Memory)
void MacroAssembler::SubS32(Register dst, const MemOperand& opnd) {
  DCHECK(is_int20(opnd.offset()));
  if (is_uint12(opnd.offset()))
    s(dst, opnd);
  else
    sy(dst, opnd);
}

// Subtract Pointer Sized (Register - Memory)
void MacroAssembler::SubS64(Register dst, const MemOperand& opnd) {
  sg(dst, opnd);
}

void MacroAssembler::MovIntToFloat(DoubleRegister dst, Register src) {
  sllg(r0, src, Operand(32));
  ldgr(dst, r0);
}

void MacroAssembler::MovFloatToInt(Register dst, DoubleRegister src) {
  lgdr(dst, src);
  srlg(dst, dst, Operand(32));
}

// Load And Subtract 32-bit (similar to laa/lan/lao/lax)
void MacroAssembler::LoadAndSub32(Register dst, Register src,
                                  const MemOperand& opnd) {
  lcr(dst, src);
  laa(dst, dst, opnd);
}

void MacroAssembler::LoadAndSub64(Register dst, Register src,
                                  const MemOperand& opnd) {
  lcgr(dst, src);
  laag(dst, dst, opnd);
}

//----------------------------------------------------------------------------
//  Subtract Logical Instructions
//----------------------------------------------------------------------------

// Subtract Logical 32-bit (Register - Memory)
void MacroAssembler::SubU32(Register dst, const MemOperand& opnd) {
  DCHECK(is_int20(opnd.offset()));
  if (is_uint12(opnd.offset()))
    sl(dst, opnd);
  else
    sly(dst, opnd);
}

// Subtract Logical Pointer Sized (Register - Memory)
void MacroAssembler::SubU64(Register dst, const MemOperand& opnd) {
  DCHECK(is_int20(opnd.offset()));
  slgf(dst, opnd);
}

//----------------------------------------------------------------------------
//  Bitwise Operations
//----------------------------------------------------------------------------

// AND 32-bit - dst = dst & src
void MacroAssembler::And(Register dst, Register src) { nr(dst, src); }

// AND Pointer Size - dst = dst & src
void MacroAssembler::AndP(Register dst, Register src) { ngr(dst, src); }

// Non-clobbering AND 32-bit - dst = src1 & src1
void MacroAssembler::And(Register dst, Register src1, Register src2) {
  if (dst != src1 && dst != src2) {
    // We prefer to generate XR/XGR, over the non clobbering XRK/XRK
    // as XR is a smaller instruction
    if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
      nrk(dst, src1, src2);
      return;
    } else {
      lr(dst, src1);
    }
  } else if (dst == src2) {
    src2 = src1;
  }
  And(dst, src2);
}

// Non-clobbering AND pointer size - dst = src1 & src1
void MacroAssembler::AndP(Register dst, Register src1, Register src2) {
  if (dst != src1 && dst != src2) {
    // We prefer to generate XR/XGR, over the non clobbering XRK/XRK
    // as XR is a smaller instruction
    if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
      ngrk(dst, src1, src2);
      return;
    } else {
      mov(dst, src1);
    }
  } else if (dst == src2) {
    src2 = src1;
  }
  AndP(dst, src2);
}

// AND 32-bit (Reg - Mem)
void MacroAssembler::And(Register dst, const MemOperand& opnd) {
  DCHECK(is_int20(opnd.offset()));
  if (is_uint12(opnd.offset()))
    n(dst, opnd);
  else
    ny(dst, opnd);
}

// AND Pointer Size (Reg - Mem)
void MacroAssembler::AndP(Register dst, const MemOperand& opnd) {
  DCHECK(is_int20(opnd.offset()));
  ng(dst, opnd);
}

// AND 32-bit - dst = dst & imm
void MacroAssembler::And(Register dst, const Operand& opnd) { nilf(dst, opnd); }

// AND Pointer Size - dst = dst & imm
void MacroAssembler::AndP(Register dst, const Operand& opnd) {
  intptr_t value = opnd.immediate();
  if (value >> 32 != -1) {
    // this may not work b/c condition code won't be set correctly
    nihf(dst, Operand(value >> 32));
  }
  nilf(dst, Operand(value & 0xFFFFFFFF));
}

// AND 32-bit - dst = src & imm
void MacroAssembler::And(Register dst, Register src, const Operand& opnd) {
  if (dst != src) lr(dst, src);
  nilf(dst, opnd);
}

// AND Pointer Size - dst = src & imm
void MacroAssembler::AndP(Register dst, Register src, const Operand& opnd) {
  // Try to exploit RISBG first
  intptr_t value = opnd.immediate();
  if (CpuFeatures::IsSupported(GENERAL_INSTR_EXT)) {
    intptr_t shifted_value = value;
    int trailing_zeros = 0;

    // We start checking how many trailing zeros are left at the end.
    while ((0 != shifted_value) && (0 == (shifted_value & 1))) {
      trailing_zeros++;
      shifted_value >>= 1;
    }

    // If temp (value with right-most set of zeros shifted out) is 1 less
    // than power of 2, we have consecutive bits of 1.
    // Special case: If shift_value is zero, we cannot use RISBG, as it requires
    //               selection of at least 1 bit.
    if ((0 != shifted_value) && base::bits::IsPowerOfTwo(shifted_value + 1)) {
      int startBit =
          base::bits::CountLeadingZeros64(shifted_value) - trailing_zeros;
      int endBit = 63 - trailing_zeros;
      // Start: startBit, End: endBit, Shift = 0, true = zero unselected bits.
      RotateInsertSelectBits(dst, src, Operand(startBit), Operand(endBit),
                             Operand::Zero(), true);
      return;
    } else if (-1 == shifted_value) {
      // A Special case in which all top bits up to MSB are 1's.  In this case,
      // we can set startBit to be 0.
      int endBit = 63 - trailing_zeros;
      RotateInsertSelectBits(dst, src, Operand::Zero(), Operand(endBit),
                             Operand::Zero(), true);
      return;
    }
  }

  // If we are &'ing zero, we can just whack the dst register and skip copy
  if (dst != src && (0 != value)) mov(dst, src);
  AndP(dst, opnd);
}

// OR 32-bit - dst = dst & src
void MacroAssembler::Or(Register dst, Register src) { or_z(dst, src); }

// OR Pointer Size - dst = dst & src
void MacroAssembler::OrP(Register dst, Register src) { ogr(dst, src); }

// Non-clobbering OR 32-bit - dst = src1 & src1
void MacroAssembler::Or(Register dst, Register src1, Register src2) {
  if (dst != src1 && dst != src2) {
    // We prefer to generate XR/XGR, over the non clobbering XRK/XRK
    // as XR is a smaller instruction
    if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
      ork(dst, src1, src2);
      return;
    } else {
      lr(dst, src1);
    }
  } else if (dst == src2) {
    src2 = src1;
  }
  Or(dst, src2);
}

// Non-clobbering OR pointer size - dst = src1 & src1
void MacroAssembler::OrP(Register dst, Register src1, Register src2) {
  if (dst != src1 && dst != src2) {
    // We prefer to generate XR/XGR, over the non clobbering XRK/XRK
    // as XR is a smaller instruction
    if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
      ogrk(dst, src1, src2);
      return;
    } else {
      mov(dst, src1);
    }
  } else if (dst == src2) {
    src2 = src1;
  }
  OrP(dst, src2);
}

// OR 32-bit (Reg - Mem)
void MacroAssembler::Or(Register dst, const MemOperand& opnd) {
  DCHECK(is_int20(opnd.offset()));
  if (is_uint12(opnd.offset()))
    o(dst, opnd);
  else
    oy(dst, opnd);
}

// OR Pointer Size (Reg - Mem)
void MacroAssembler::OrP(Register dst, const MemOperand& opnd) {
  DCHECK(is_int20(opnd.offset()));
  og(dst, opnd);
}

// OR 32-bit - dst = dst & imm
void MacroAssembler::Or(Register dst, const Operand& opnd) { oilf(dst, opnd); }

// OR Pointer Size - dst = dst & imm
void MacroAssembler::OrP(Register dst, const Operand& opnd) {
  intptr_t value = opnd.immediate();
  if (value >> 32 != 0) {
    // this may not work b/c condition code won't be set correctly
    oihf(dst, Operand(value >> 32));
  }
  oilf(dst, Operand(value & 0xFFFFFFFF));
}

// OR 32-bit - dst = src & imm
void MacroAssembler::Or(Register dst, Register src, const Operand& opnd) {
  if (dst != src) lr(dst, src);
  oilf(dst, opnd);
}

// OR Pointer Size - dst = src & imm
void MacroAssembler::OrP(Register dst, Register src, const Operand& opnd) {
  if (dst != src) mov(dst, src);
  OrP(dst, opnd);
}

// XOR 32-bit - dst = dst & src
void MacroAssembler::Xor(Register dst, Register src) { xr(dst, src); }

// XOR Pointer Size - dst = dst & src
void MacroAssembler::XorP(Register dst, Register src) { xgr(dst, src); }

// Non-clobbering XOR 32-bit - dst = src1 & src1
void MacroAssembler::Xor(Register dst, Register src1, Register src2) {
  if (dst != src1 && dst != src2) {
    // We prefer to generate XR/XGR, over the non clobbering XRK/XRK
    // as XR is a smaller instruction
    if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
      xrk(dst, src1, src2);
      return;
    } else {
      lr(dst, src1);
    }
  } else if (dst == src2) {
    src2 = src1;
  }
  Xor(dst, src2);
}

// Non-clobbering XOR pointer size - dst = src1 & src1
void MacroAssembler::XorP(Register dst, Register src1, Register src2) {
  if (dst != src1 && dst != src2) {
    // We prefer to generate XR/XGR, over the non clobbering XRK/XRK
    // as XR is a smaller instruction
    if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
      xgrk(dst, src1, src2);
      return;
    } else {
      mov(dst, src1);
    }
  } else if (dst == src2) {
    src2 = src1;
  }
  XorP(dst, src2);
}

// XOR 32-bit (Reg - Mem)
void MacroAssembler::Xor(Register dst, const MemOperand& opnd) {
  DCHECK(is_int20(opnd.offset()));
  if (is_uint12(opnd.offset()))
    x(dst, opnd);
  else
    xy(dst, opnd);
}

// XOR Pointer Size (Reg - Mem)
void MacroAssembler::XorP(Register dst, const MemOperand& opnd) {
  DCHECK(is_int20(opnd.offset()));
  xg(dst, opnd);
}

// XOR 32-bit - dst = dst & imm
void MacroAssembler::Xor(Register dst, const Operand& opnd) { xilf(dst, opnd); }

// XOR Pointer Size - dst = dst & imm
void MacroAssembler::XorP(Register dst, const Operand& opnd) {
  intptr_t value = opnd.immediate();
  xihf(dst, Operand(value >> 32));
  xilf(dst, Operand(value & 0xFFFFFFFF));
}

// XOR 32-bit - dst = src & imm
void MacroAssembler::Xor(Register dst, Register src, const Operand& opnd) {
  if (dst != src) lr(dst, src);
  xilf(dst, opnd);
}

// XOR Pointer Size - dst = src & imm
void MacroAssembler::XorP(Register dst, Register src, const Operand& opnd) {
  if (dst != src) mov(dst, src);
  XorP(dst, opnd);
}

void MacroAssembler::Not32(Register dst, Register src) {
  if (src != no_reg && src != dst) lr(dst, src);
  xilf(dst, Operand(0xFFFFFFFF));
}

void MacroAssembler::Not64(Register dst, Register src) {
  if (src != no_reg && src != dst) lgr(dst, src);
  xihf(dst, Operand(0xFFFFFFFF));
  xilf(dst, Operand(0xFFFFFFFF));
}

void MacroAssembler::NotP(Register dst, Register src) {
  Not64(dst, src);
}

void MacroAssembler::LoadPositiveP(Register result, Register input) {
  lpgr(result, input);
}

void MacroAssembler::LoadPositive32(Register result, Register input) {
  lpr(result, input);
  lgfr(result, result);
}

//-----------------------------------------------------------------------------
//  Compare Helpers
//-----------------------------------------------------------------------------

// Compare 32-bit Register vs Register
void MacroAssembler::CmpS32(Register src1, Register src2) { cr_z(src1, src2); }

// Compare Pointer Sized Register vs Register
void MacroAssembler::CmpS64(Register src1, Register src2) { cgr(src1, src2); }

// Compare 32-bit Register vs Immediate
// This helper will set up proper relocation entries if required.
void MacroAssembler::CmpS32(Register dst, const Operand& opnd) {
  if (opnd.rmode() == RelocInfo::NO_INFO) {
    intptr_t value = opnd.immediate();
    if (is_int16(value))
      chi(dst, opnd);
    else
      cfi(dst, opnd);
  } else {
    // Need to generate relocation record here
    RecordRelocInfo(opnd.rmode(), opnd.immediate());
    cfi(dst, opnd);
  }
}

// Compare Pointer Sized  Register vs Immediate
// This helper will set up proper relocation entries if required.
void MacroAssembler::CmpS64(Register dst, const Operand& opnd) {
  if (opnd.rmode() == RelocInfo::NO_INFO) {
    cgfi(dst, opnd);
  } else {
    mov(r0, opnd);  // Need to generate 64-bit relocation
    cgr(dst, r0);
  }
}

// Compare 32-bit Register vs Memory
void MacroAssembler::CmpS32(Register dst, const MemOperand& opnd) {
  // make sure offset is within 20 bit range
  DCHECK(is_int20(opnd.offset()));
  if (is_uint12(opnd.offset()))
    c(dst, opnd);
  else
    cy(dst, opnd);
}

// Compare Pointer Size Register vs Memory
void MacroAssembler::CmpS64(Register dst, const MemOperand& opnd) {
  // make sure offset is within 20 bit range
  DCHECK(is_int20(opnd.offset()));
  cg(dst, opnd);
}

void MacroAssembler::CmpF32(DoubleRegister src1, DoubleRegister src2) {
  cebr(src1, src2);
}

void MacroAssembler::CmpF64(DoubleRegister src1, DoubleRegister src2) {
  cdbr(src1, src2);
}

void MacroAssembler::CmpF32(DoubleRegister src1, const MemOperand& src2) {
  DCHECK(is_int12(src2.offset()));
  ceb(src1, src2);
}

void MacroAssembler::CmpF64(DoubleRegister src1, const MemOperand& src2) {
  DCHECK(is_int12(src2.offset()));
  cdb(src1, src2);
}

// Using cs or scy based on the offset
void MacroAssembler::CmpAndSwap(Register old_val, Register new_val,
                                const MemOperand& opnd) {
  if (is_uint12(opnd.offset())) {
    cs(old_val, new_val, opnd);
  } else {
    csy(old_val, new_val, opnd);
  }
}

void MacroAssembler::CmpAndSwap64(Register old_val, Register new_val,
                                  const MemOperand& opnd) {
  DCHECK(is_int20(opnd.offset()));
  csg(old_val, new_val, opnd);
}

//-----------------------------------------------------------------------------
// Compare Logical Helpers
//-----------------------------------------------------------------------------

// Compare Logical 32-bit Register vs Register
void MacroAssembler::CmpU32(Register dst, Register src) { clr(dst, src); }

// Compare Logical Pointer Sized Register vs Register
void MacroAssembler::CmpU64(Register dst, Register src) {
  clgr(dst, src);
}

// Compare Logical 32-bit Register vs Immediate
void MacroAssembler::CmpU32(Register dst, const Operand& opnd) {
  clfi(dst, opnd);
}

// Compare Logical Pointer Sized Register vs Immediate
void MacroAssembler::CmpU64(Register dst, const Operand& opnd) {
  DCHECK_EQ(static_cast<uint32_t>(opnd.immediate() >> 32), 0);
  clgfi(dst, opnd);
}

// Compare Logical 32-bit Register vs Memory
void MacroAssembler::CmpU32(Register dst, const MemOperand& opnd) {
  // make sure offset is within 20 bit range
  DCHECK(is_int20(opnd.offset()));
  if (is_uint12(opnd.offset()))
    cl(dst, opnd);
  else
    cly(dst, opnd);
}

// Compare Logical Pointer Sized Register vs Memory
void MacroAssembler::CmpU64(Register dst, const MemOperand& opnd) {
  // make sure offset is within 20 bit range
  DCHECK(is_int20(opnd.offset()));
  clg(dst, opnd);
}

void MacroAssembler::Branch(Condition c, const Operand& opnd) {
  intptr_t value = opnd.immediate();
  if (is_int16(value))
    brc(c, opnd);
  else
    brcl(c, opnd);
}

// Branch On Count.  Decrement R1, and branch if R1 != 0.
void MacroAssembler::BranchOnCount(Register r1, Label* l) {
  int32_t offset = branch_offset(l);
  if (is_int16(offset)) {
    brctg(r1, Operand(offset));
  } else {
    AddS64(r1, Operand(-1));
    Branch(ne, Operand(offset));
  }
}

void MacroAssembler::LoadSmiLiteral(Register dst, Tagged<Smi> smi) {
  intptr_t value = static_cast<intptr_t>(smi.ptr());
#if defined(V8_COMPRESS_POINTERS) || defined(V8_31BIT_SMIS_ON_64BIT_ARCH)
  llilf(dst, Operand(value));
#else
  DCHECK_EQ(value & 0xFFFFFFFF, 0);
  // The smi value is loaded in upper 32-bits.  Lower 32-bit are zeros.
  llihf(dst, Operand(value >> 32));
#endif
}

void MacroAssembler::CmpSmiLiteral(Register src1, Tagged<Smi> smi,
                                   Register scratch) {
#if defined(V8_COMPRESS_POINTERS) || defined(V8_31BIT_SMIS_ON_64BIT_ARCH)
  // CFI takes 32-bit immediate.
  cfi(src1, Operand(smi));
#else
  if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
    cih(src1, Operand(static_cast<intptr_t>(smi.ptr()) >> 32));
  } else {
    LoadSmiLiteral(scratch, smi);
    cgr(src1, scratch);
  }
#endif
}

void MacroAssembler::LoadU64(Register dst, const MemOperand& mem,
                             Register scratch) {
  int offset = mem.offset();

  MemOperand src = mem;
  if (!is_int20(offset)) {
    DCHECK(scratch != no_reg && scratch != r0 && mem.rx() == r0);
    DCHECK(scratch != mem.rb());
    mov(scratch, Operand(offset));
    src = MemOperand(mem.rb(), scratch);
  }
  lg(dst, src);
}

// Store a "pointer" sized value to the memory location
void MacroAssembler::StoreU64(Register src, const MemOperand& mem,
                              Register scratch) {
  if (!is_int20(mem.offset())) {
    DCHECK(scratch != no_reg);
    DCHECK(scratch != r0);
    mov(scratch, Operand(mem.offset()));
    stg(src, MemOperand(mem.rb(), scratch));
  } else {
    stg(src, mem);
  }
}

// Store a "pointer" sized constant to the memory location
void MacroAssembler::StoreU64(const MemOperand& mem, const Operand& opnd,
                              Register scratch) {
  // Relocations not supported
  DCHECK_EQ(opnd.rmode(), RelocInfo::NO_INFO);

  // Try to use MVGHI/MVHI
  if (CpuFeatures::IsSupported(GENERAL_INSTR_EXT) && is_uint12(mem.offset()) &&
      mem.getIndexRegister() == r0 && is_int16(opnd.immediate())) {
    mvghi(mem, opnd);
  } else {
    mov(scratch, opnd);
    StoreU64(scratch, mem);
  }
}

void MacroAssembler::LoadMultipleP(Register dst1, Register dst2,
                                   const MemOperand& mem) {
  DCHECK(is_int20(mem.offset()));
  lmg(dst1, dst2, mem);
}

void MacroAssembler::StoreMultipleP(Register src1, Register src2,
                                    const MemOperand& mem) {
  DCHECK(is_int20(mem.offset()));
  stmg(src1, src2, mem);
}

void MacroAssembler::LoadMultipleW(Register dst1, Register dst2,
                                   const MemOperand& mem) {
  if (is_uint12(mem.offset())) {
    lm(dst1, dst2, mem);
  } else {
    DCHECK(is_int20(mem.offset()));
    lmy(dst1, dst2, mem);
  }
}

void MacroAssembler::StoreMultipleW(Register src1, Register src2,
                                    const MemOperand& mem) {
  if (is_uint12(mem.offset())) {
    stm(src1, src2, mem);
  } else {
    DCHECK(is_int20(mem.offset()));
    stmy(src1, src2, mem);
  }
}

// Load 32-bits and sign extend if necessary.
void MacroAssembler::LoadS32(Register dst, Register src) {
  lgfr(dst, src);
}

// Load 32-bits and sign extend if necessary.
void MacroAssembler::LoadS32(Register dst, const MemOperand& mem,
                             Register scratch) {
  int offset = mem.offset();

  if (!is_int20(offset)) {
    DCHECK(scratch != no_reg);
    mov(scratch, Operand(offset));
    lgf(dst, MemOperand(mem.rb(), scratch));
  } else {
    lgf(dst, mem);
  }
}

// Load 32-bits and zero extend if necessary.
void MacroAssembler::LoadU32(Register dst, Register src) {
  llgfr(dst, src);
}

// Variable length depending on whether offset fits into immediate field
// MemOperand of RX or RXY format
void MacroAssembler::LoadU32(Register dst, const MemOperand& mem,
                             Register scratch) {
  Register base = mem.rb();
  int offset = mem.offset();

  if (is_int20(offset)) {
    llgf(dst, mem);
  } else if (scratch != no_reg) {
    // Materialize offset into scratch register.
    mov(scratch, Operand(offset));
    llgf(dst, MemOperand(base, scratch));
  } else {
    DCHECK(false);
  }
}

void MacroAssembler::LoadU16(Register dst, const MemOperand& mem) {
  // TODO(s390x): Add scratch reg
  llgh(dst, mem);
}

void MacroAssembler::LoadU16(Register dst, Register src) {
  llghr(dst, src);
}

void MacroAssembler::LoadS8(Register dst, const MemOperand& mem) {
  // TODO(s390x): Add scratch reg
  lgb(dst, mem);
}

void MacroAssembler::LoadS8(Register dst, Register src) {
  lgbr(dst, src);
}

void MacroAssembler::LoadU8(Register dst, const MemOperand& mem) {
  // TODO(s390x): Add scratch reg
  llgc(dst, mem);
}

void MacroAssembler::LoadU8(Register dst, Register src) {
  llgcr(dst, src);
}

#ifdef V8_TARGET_BIG_ENDIAN
void MacroAssembler::LoadU64LE(Register dst, const MemOperand& mem,
                               Register scratch) {
  lrvg(dst, mem);
}

void MacroAssembler::LoadS32LE(Register dst, const MemOperand& opnd,
                               Register scratch) {
  lrv(dst, opnd);
  L
"""


```