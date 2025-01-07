Response:
The user wants a summary of the functionality of the provided C++ code snippet. This code is part of V8's LoongArch64 macro-assembler.

Here's a breakdown of the code's functionality:

1. **Comparison Operations:** The code defines functions for performing comparisons (less than, less than or equal to, greater than, greater than or equal to) between registers and operands (registers or immediate values). These functions often optimize for immediate values, using immediate versions of the instructions when possible. If the immediate value is too large or complex, it loads the immediate value into a temporary register first.

2. **Rotate Operations:** Functions `Rotr_w` and `Rotr_d` implement right rotate operations on word (32-bit) and doubleword (64-bit) values respectively. They handle both register and immediate operands.

3. **Arithmetic Shift Left and Add (Alsl):**  `Alsl_w` and `Alsl_d` implement an optimized arithmetic shift left and add operation. It leverages the `alsl` instruction when the shift amount is small and falls back to separate shift and add instructions for larger shifts.

4. **Pseudo Instructions:** This section provides higher-level abstractions over the basic LoongArch64 instructions.

5. **Byte Swap:** `ByteSwap` changes the endianness of a value.

6. **Load and Store Instructions:**  Functions like `Ld_b`, `St_b`, `Ld_h`, `St_h`, `Ld_w`, `St_w`, `Ld_d`, `St_d` and their unsigned counterparts provide convenient ways to load and store data of different sizes (byte, half-word, word, doubleword) from memory. They handle cases where an index register is used and optimize for common scenarios like aligned word/doubleword loads/stores with small offsets.

7. **Floating-Point Load and Store:** `Fld_s`, `Fst_s`, `Fld_d`, `Fst_d` handle loading and storing single-precision and double-precision floating-point values from memory.

8. **Load Linked and Store Conditional:** `Ll_w`, `Ll_d`, `Sc_w`, `Sc_d` implement atomic load and store operations, crucial for multi-threaded programming.

9. **Load Immediate (li):**  The `li` function is responsible for loading immediate values into registers. It's heavily optimized to handle different sizes and types of immediates, including heap objects and external references. It uses different instruction sequences depending on the immediate's value to minimize code size or execution time.

10. **Stack Manipulation:** `MultiPush` and `MultiPop` simplify pushing and popping multiple registers onto/from the stack.

11. **Bit Field Manipulation:** `Bstrpick_w` and `Bstrpick_d` extract a bit field from a register.

12. **Floating-Point Negation:** `Neg_s` and `Neg_d` negate single and double-precision floating-point numbers.

13. **Floating-Point Integer Conversion:** A series of `Ffint` functions convert floating-point numbers to unsigned integer representations. They handle cases where the floating-point value is larger than the maximum representable integer.

14. **Floating-Point Truncation to Integer:** `Ftintrne_l_d`, `Ftintrm_l_d`, `Ftintrp_l_d`, `Ftintrz_l_d`, and their word counterparts truncate floating-point numbers to integers using different rounding modes. Optimized versions for unsigned conversions (`Ftintrz_uw_d`, `Ftintrz_ul_d`, etc.) are also provided.

15. **Floating-Point Rounding:** `RoundDouble` and `RoundFloat` provide functions to round floating-point numbers to the nearest integer using different rounding modes (floor, ceiling, truncate, round to nearest).

16. **Floating-Point Comparison:** `CompareF` compares two floating-point registers.

**Overall Functionality:**

This code snippet provides a set of macro-assembler functions for the LoongArch64 architecture within the V8 JavaScript engine. These functions abstract away the raw assembly instructions, providing a more convenient and higher-level interface for generating machine code. The focus is on providing common operations needed for compiling JavaScript code, including arithmetic, memory access, and floating-point operations, with optimizations for performance and code size.
这是 v8 源代码文件 `v8/src/codegen/loong64/macro-assembler-loong64.cc` 的一部分，它定义了 `MacroAssembler` 类的一些方法，用于生成 LoongArch64 架构的机器码。

**归纳其功能，这部分代码主要实现了以下功能：**

1. **条件比较指令的封装:**  定义了 `Slt`, `Sltu`, `Sle`, `Sleu`, `Sge`, `Sgeu`, `Sgt`, `Sgtu` 等函数，用于实现小于、小于等于、大于、大于等于等比较操作。这些函数接受寄存器和操作数（可以是寄存器或立即数），并根据操作数的类型选择合适的 LoongArch64 指令（如 `slt`, `slti` 等）。如果立即数过大或需要重定位，还会使用临时寄存器加载立即数。

2. **循环移位指令的封装:** 定义了 `Rotr_w` 和 `Rotr_d` 函数，用于实现 32 位和 64 位的右循环移位操作。同样支持寄存器和立即数作为移位量。

3. **优化的算术左移加法指令:** 定义了 `Alsl_w` 和 `Alsl_d` 函数，用于实现算术左移后再加到另一个寄存器的操作。当左移位数较小时，直接使用 `alsl` 指令，否则使用 `slli` 和 `add` 指令组合。

4. **伪指令的实现:**  这部分定义了一些更高级的指令，实际上是对多个底层 LoongArch64 指令的封装，提供了更方便的编程接口。

5. **字节序转换:** `ByteSwap` 函数用于转换数据的字节序。

6. **内存加载和存储指令的封装:**  定义了 `Ld_b`, `Ld_bu`, `St_b`, `Ld_h`, `Ld_hu`, `St_h`, `Ld_w`, `Ld_wu`, `St_w`, `Ld_d`, `St_d` 等函数，用于加载和存储不同大小的数据（字节、半字、字、双字）。这些函数考虑了内存操作数的不同形式（带立即数偏移或带索引寄存器），并针对特定情况进行了优化，例如对齐的字或双字加载存储。

7. **浮点数加载和存储指令的封装:** 定义了 `Fld_s`, `Fst_s`, `Fld_d`, `Fst_d` 函数，用于加载和存储单精度和双精度浮点数。

8. **原子加载和存储指令的封装:** 定义了 `Ll_w`, `Ll_d`, `Sc_w`, `Sc_d` 函数，用于实现原子加载和条件存储操作，常用于多线程编程中的同步。

9. **加载立即数 (li) 指令的优化实现:**  `li` 函数用于将立即数或内存地址加载到寄存器中。这个函数进行了大量的优化，针对不同大小和类型的立即数（包括嵌入式对象和外部引用），采用不同的指令序列，以尽可能减少代码大小或提高效率。  它还考虑了代码是否为独立隔离代码的情况。

10. **批量入栈和出栈操作:** `MultiPush` 和 `MultiPop` 函数用于一次性将多个通用寄存器或浮点寄存器压入或弹出栈。

11. **位域提取指令:** `Bstrpick_w` 和 `Bstrpick_d` 函数用于从寄存器中提取指定范围的位。

12. **浮点数取负:** `Neg_s` 和 `Neg_d` 函数用于对单精度和双精度浮点数取负。

13. **浮点数转换为无符号整数:** `Ffint_d_uw`, `Ffint_d_ul`, `Ffint_s_uw`, `Ffint_s_ul` 等函数将浮点数转换为无符号整数。这些函数需要处理浮点数超出整数表示范围的情况。

14. **浮点数截断为整数:** `Ftintrne_l_d`, `Ftintrm_l_d`, `Ftintrp_l_d`, `Ftintrz_l_d` 等函数将浮点数截断为整数，并提供不同的舍入模式。还提供了针对无符号整数的优化版本，例如 `Ftintrz_uw_d` 和 `Ftintrz_ul_d`，这些版本需要处理超出无符号整数表示范围的情况。

15. **浮点数舍入:** `RoundDouble` 和 `RoundFloat` 函数用于将浮点数舍入到最接近的整数，支持不同的舍入模式（floor, ceil, trunc, round）。

16. **浮点数比较指令的封装:** `CompareF` 函数用于比较两个浮点寄存器。

**关于代码特性：**

* **面向 LoongArch64 架构:** 代码中使用的指令名称（如 `slt`, `slti`, `rotr_w`, `ld_w` 等）都是 LoongArch64 架构的汇编指令。
* **宏汇编:** `MacroAssembler` 类的作用是提供一个更高级的接口来生成汇编代码，避免直接操作底层的二进制指令。
* **优化:** 代码中针对不同的操作数类型和值范围进行了优化，例如 `li` 指令会根据立即数的大小选择最优的加载方式。
* **处理内存操作数:** 许多函数都接受 `MemOperand` 类型的参数，用于描述内存操作数，包括基址寄存器、偏移量和索引寄存器。
* **使用临时寄存器:** 在某些情况下，为了完成复杂的操作或处理立即数，代码会使用临时寄存器。
* **浮点运算:** 代码中包含了对浮点数的加载、存储、比较、转换和舍入等操作的支持。

**如果 v8/src/codegen/loong64/macro-assembler-loong64.cc 以 .tq 结尾，那它是个 v8 torque 源代码。** 但根据您提供的信息，它以 `.cc` 结尾，所以是 C++ 源代码。 Torque 是一种 V8 特有的语言，用于生成高效的运行时代码。

**与 JavaScript 的功能关系:**

这段代码是 V8 引擎的一部分，负责将 JavaScript 代码编译成可执行的机器码。  它直接参与了 JavaScript 引擎的底层实现，使得 JavaScript 代码能够在 LoongArch64 架构的处理器上运行。

**JavaScript 示例：**

以下是一些 JavaScript 代码片段，它们背后的编译过程可能会涉及到这里列出的 `MacroAssembler` 方法：

```javascript
// 比较操作
if (a < b) { ... }
if (x >= 10) { ... }

// 算术运算
let c = a + (b << 4); // 左移操作可能用到 Alsl

// 内存访问 (例如访问数组元素)
let value = array[i];
object.property = newValue;

// 浮点数运算
let result = Math.sqrt(number);
let rounded = Math.floor(floatValue);

// 类型转换
let intValue = parseInt(floatValue);

// 原子操作 (用于多线程/共享内存)
// (JavaScript 中虽然不直接暴露原子操作，但在底层实现中可能会用到)
```

当 V8 编译这些 JavaScript 代码时，`MacroAssembler` 类的方法会被调用，生成相应的 LoongArch64 机器码来执行这些操作。例如，`a < b` 的比较可能会调用 `Slt` 函数，`Math.floor(floatValue)` 可能会调用 `Floor_d` 或 `Floor_s` 函数。

**代码逻辑推理示例 (假设输入与输出):**

假设输入以下调用：

```c++
MacroAssembler masm;
Register r1 = kReg0; // 假设 kReg0 代表一个通用寄存器
Register r2 = kReg1;
masm.Slt(r1, r2, Operand(10));
```

**假设输入:**

* `r1`  指向 LoongArch64 的一个通用寄存器 (例如，寄存器 `x0`).
* `r2` 指向另一个通用寄存器 (例如，寄存器 `x1`).
* `Operand(10)` 表示一个立即数 10。

**代码逻辑推理:**

1. `masm.Slt(r1, r2, Operand(10))` 调用 `MacroAssembler::Slt` 函数。
2. `Operand(10)` 是一个立即数，且 10 可以用 12 位有符号数表示 (`is_int12(10)` 为真)。
3. 因此，`Slt` 函数内部会调用 `slti(r1, r2, 10)` 指令。

**预期输出 (生成的汇编代码片段):**

```assembly
slti x0, x1, 10
```

这条指令会将 `r2` 的值与立即数 10 进行有符号比较，如果 `r2` 小于 10，则将 1 写入 `r1`，否则写入 0。

**用户常见的编程错误示例:**

这段代码本身是 V8 引擎的实现细节，普通 JavaScript 开发者不会直接编写或修改它。但是，理解其功能有助于理解 V8 如何处理某些 JavaScript 操作，以及潜在的性能影响。

与这段代码相关的常见编程错误可能发生在 V8 引擎的开发过程中，例如：

* **错误的指令选择:**  选择了不适合当前操作数类型的指令，例如尝试对一个超出范围的立即数使用立即数版本的指令。
* **寄存器冲突:**  在需要使用临时寄存器时，没有正确管理寄存器的分配，导致寄存器被意外覆盖。 这段代码中使用了 `UseScratchRegisterScope` 来帮助管理临时寄存器。
* **内存操作错误:**  计算错误的内存地址或使用错误的加载/存储指令大小，导致数据读取或写入错误。  `AdjustBaseAndOffset` 函数的作用之一就是帮助处理内存地址计算。
* **浮点数运算的精度问题:**  在浮点数转换或舍入时，没有考虑到精度损失或不同的舍入模式，导致结果不符合预期。

总之，这段代码是 V8 引擎中用于生成高效 LoongArch64 机器码的关键组成部分，它封装了各种指令，并进行了优化，以支持 JavaScript 代码的执行。

Prompt: 
```
这是目录为v8/src/codegen/loong64/macro-assembler-loong64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/loong64/macro-assembler-loong64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共6部分，请归纳一下它的功能

"""
ter rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    slt(rd, rj, rk.rm());
  } else {
    if (is_int12(rk.immediate()) && !MustUseReg(rk.rmode())) {
      slti(rd, rj, static_cast<int32_t>(rk.immediate()));
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      BlockTrampolinePoolScope block_trampoline_pool(this);
      Register scratch = temps.hasAvailable() ? temps.Acquire() : t8;
      DCHECK(rj != scratch);
      li(scratch, rk);
      slt(rd, rj, scratch);
    }
  }
}

void MacroAssembler::Sltu(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    sltu(rd, rj, rk.rm());
  } else {
    if (is_int12(rk.immediate()) && !MustUseReg(rk.rmode())) {
      sltui(rd, rj, static_cast<int32_t>(rk.immediate()));
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      BlockTrampolinePoolScope block_trampoline_pool(this);
      Register scratch = temps.hasAvailable() ? temps.Acquire() : t8;
      DCHECK(rj != scratch);
      li(scratch, rk);
      sltu(rd, rj, scratch);
    }
  }
}

void MacroAssembler::Sle(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    slt(rd, rk.rm(), rj);
  } else {
    if (rk.immediate() == 0 && !MustUseReg(rk.rmode())) {
      slt(rd, zero_reg, rj);
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.hasAvailable() ? temps.Acquire() : t8;
      BlockTrampolinePoolScope block_trampoline_pool(this);
      DCHECK(rj != scratch);
      li(scratch, rk);
      slt(rd, scratch, rj);
    }
  }
  xori(rd, rd, 1);
}

void MacroAssembler::Sleu(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    sltu(rd, rk.rm(), rj);
  } else {
    if (rk.immediate() == 0 && !MustUseReg(rk.rmode())) {
      sltu(rd, zero_reg, rj);
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.hasAvailable() ? temps.Acquire() : t8;
      BlockTrampolinePoolScope block_trampoline_pool(this);
      DCHECK(rj != scratch);
      li(scratch, rk);
      sltu(rd, scratch, rj);
    }
  }
  xori(rd, rd, 1);
}

void MacroAssembler::Sge(Register rd, Register rj, const Operand& rk) {
  Slt(rd, rj, rk);
  xori(rd, rd, 1);
}

void MacroAssembler::Sgeu(Register rd, Register rj, const Operand& rk) {
  Sltu(rd, rj, rk);
  xori(rd, rd, 1);
}

void MacroAssembler::Sgt(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    slt(rd, rk.rm(), rj);
  } else {
    if (rk.immediate() == 0 && !MustUseReg(rk.rmode())) {
      slt(rd, zero_reg, rj);
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.hasAvailable() ? temps.Acquire() : t8;
      BlockTrampolinePoolScope block_trampoline_pool(this);
      DCHECK(rj != scratch);
      li(scratch, rk);
      slt(rd, scratch, rj);
    }
  }
}

void MacroAssembler::Sgtu(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    sltu(rd, rk.rm(), rj);
  } else {
    if (rk.immediate() == 0 && !MustUseReg(rk.rmode())) {
      sltu(rd, zero_reg, rj);
    } else {
      // li handles the relocation.
      UseScratchRegisterScope temps(this);
      Register scratch = temps.hasAvailable() ? temps.Acquire() : t8;
      BlockTrampolinePoolScope block_trampoline_pool(this);
      DCHECK(rj != scratch);
      li(scratch, rk);
      sltu(rd, scratch, rj);
    }
  }
}

void MacroAssembler::Rotr_w(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    rotr_w(rd, rj, rk.rm());
  } else {
    int64_t ror_value = rk.immediate() % 32;
    if (ror_value < 0) {
      ror_value += 32;
    }
    rotri_w(rd, rj, ror_value);
  }
}

void MacroAssembler::Rotr_d(Register rd, Register rj, const Operand& rk) {
  if (rk.is_reg()) {
    rotr_d(rd, rj, rk.rm());
  } else {
    int64_t dror_value = rk.immediate() % 64;
    if (dror_value < 0) dror_value += 64;
    rotri_d(rd, rj, dror_value);
  }
}

void MacroAssembler::Alsl_w(Register rd, Register rj, Register rk, uint8_t sa,
                            Register scratch) {
  DCHECK(sa >= 1 && sa <= 31);
  if (sa <= 4) {
    alsl_w(rd, rj, rk, sa);
  } else {
    Register tmp = rd == rk ? scratch : rd;
    DCHECK(tmp != rk);
    slli_w(tmp, rj, sa);
    add_w(rd, rk, tmp);
  }
}

void MacroAssembler::Alsl_d(Register rd, Register rj, Register rk, uint8_t sa,
                            Register scratch) {
  DCHECK(sa >= 1 && sa <= 63);
  if (sa <= 4) {
    alsl_d(rd, rj, rk, sa);
  } else {
    Register tmp = rd == rk ? scratch : rd;
    DCHECK(tmp != rk);
    slli_d(tmp, rj, sa);
    add_d(rd, rk, tmp);
  }
}

// ------------Pseudo-instructions-------------

// Change endianness
void MacroAssembler::ByteSwap(Register dest, Register src, int operand_size) {
  DCHECK(operand_size == 4 || operand_size == 8);
  if (operand_size == 4) {
    revb_2w(dest, src);
    slli_w(dest, dest, 0);
  } else {
    revb_d(dest, src);
  }
}

void MacroAssembler::Ld_b(Register rd, const MemOperand& rj) {
  MemOperand source = rj;
  AdjustBaseAndOffset(&source);
  if (source.hasIndexReg()) {
    ldx_b(rd, source.base(), source.index());
  } else {
    ld_b(rd, source.base(), source.offset());
  }
}

void MacroAssembler::Ld_bu(Register rd, const MemOperand& rj) {
  MemOperand source = rj;
  AdjustBaseAndOffset(&source);
  if (source.hasIndexReg()) {
    ldx_bu(rd, source.base(), source.index());
  } else {
    ld_bu(rd, source.base(), source.offset());
  }
}

void MacroAssembler::St_b(Register rd, const MemOperand& rj) {
  MemOperand source = rj;
  AdjustBaseAndOffset(&source);
  if (source.hasIndexReg()) {
    stx_b(rd, source.base(), source.index());
  } else {
    st_b(rd, source.base(), source.offset());
  }
}

void MacroAssembler::Ld_h(Register rd, const MemOperand& rj) {
  MemOperand source = rj;
  AdjustBaseAndOffset(&source);
  if (source.hasIndexReg()) {
    ldx_h(rd, source.base(), source.index());
  } else {
    ld_h(rd, source.base(), source.offset());
  }
}

void MacroAssembler::Ld_hu(Register rd, const MemOperand& rj) {
  MemOperand source = rj;
  AdjustBaseAndOffset(&source);
  if (source.hasIndexReg()) {
    ldx_hu(rd, source.base(), source.index());
  } else {
    ld_hu(rd, source.base(), source.offset());
  }
}

void MacroAssembler::St_h(Register rd, const MemOperand& rj) {
  MemOperand source = rj;
  AdjustBaseAndOffset(&source);
  if (source.hasIndexReg()) {
    stx_h(rd, source.base(), source.index());
  } else {
    st_h(rd, source.base(), source.offset());
  }
}

void MacroAssembler::Ld_w(Register rd, const MemOperand& rj) {
  MemOperand source = rj;

  if (!(source.hasIndexReg()) && is_int16(source.offset()) &&
      (source.offset() & 0b11) == 0) {
    ldptr_w(rd, source.base(), source.offset());
    return;
  }

  AdjustBaseAndOffset(&source);
  if (source.hasIndexReg()) {
    ldx_w(rd, source.base(), source.index());
  } else {
    ld_w(rd, source.base(), source.offset());
  }
}

void MacroAssembler::Ld_wu(Register rd, const MemOperand& rj) {
  MemOperand source = rj;
  AdjustBaseAndOffset(&source);

  if (source.hasIndexReg()) {
    ldx_wu(rd, source.base(), source.index());
  } else {
    ld_wu(rd, source.base(), source.offset());
  }
}

void MacroAssembler::St_w(Register rd, const MemOperand& rj) {
  MemOperand source = rj;

  if (!(source.hasIndexReg()) && is_int16(source.offset()) &&
      (source.offset() & 0b11) == 0) {
    stptr_w(rd, source.base(), source.offset());
    return;
  }

  AdjustBaseAndOffset(&source);
  if (source.hasIndexReg()) {
    stx_w(rd, source.base(), source.index());
  } else {
    st_w(rd, source.base(), source.offset());
  }
}

void MacroAssembler::Ld_d(Register rd, const MemOperand& rj) {
  MemOperand source = rj;

  if (!(source.hasIndexReg()) && is_int16(source.offset()) &&
      (source.offset() & 0b11) == 0) {
    ldptr_d(rd, source.base(), source.offset());
    return;
  }

  AdjustBaseAndOffset(&source);
  if (source.hasIndexReg()) {
    ldx_d(rd, source.base(), source.index());
  } else {
    ld_d(rd, source.base(), source.offset());
  }
}

void MacroAssembler::St_d(Register rd, const MemOperand& rj) {
  MemOperand source = rj;

  if (!(source.hasIndexReg()) && is_int16(source.offset()) &&
      (source.offset() & 0b11) == 0) {
    stptr_d(rd, source.base(), source.offset());
    return;
  }

  AdjustBaseAndOffset(&source);
  if (source.hasIndexReg()) {
    stx_d(rd, source.base(), source.index());
  } else {
    st_d(rd, source.base(), source.offset());
  }
}

void MacroAssembler::Fld_s(FPURegister fd, const MemOperand& src) {
  MemOperand tmp = src;
  AdjustBaseAndOffset(&tmp);
  if (tmp.hasIndexReg()) {
    fldx_s(fd, tmp.base(), tmp.index());
  } else {
    fld_s(fd, tmp.base(), tmp.offset());
  }
}

void MacroAssembler::Fst_s(FPURegister fs, const MemOperand& src) {
  MemOperand tmp = src;
  AdjustBaseAndOffset(&tmp);
  if (tmp.hasIndexReg()) {
    fstx_s(fs, tmp.base(), tmp.index());
  } else {
    fst_s(fs, tmp.base(), tmp.offset());
  }
}

void MacroAssembler::Fld_d(FPURegister fd, const MemOperand& src) {
  MemOperand tmp = src;
  AdjustBaseAndOffset(&tmp);
  if (tmp.hasIndexReg()) {
    fldx_d(fd, tmp.base(), tmp.index());
  } else {
    fld_d(fd, tmp.base(), tmp.offset());
  }
}

void MacroAssembler::Fst_d(FPURegister fs, const MemOperand& src) {
  MemOperand tmp = src;
  AdjustBaseAndOffset(&tmp);
  if (tmp.hasIndexReg()) {
    fstx_d(fs, tmp.base(), tmp.index());
  } else {
    fst_d(fs, tmp.base(), tmp.offset());
  }
}

void MacroAssembler::Ll_w(Register rd, const MemOperand& rj) {
  DCHECK(!rj.hasIndexReg());
  bool is_one_instruction = is_int14(rj.offset());
  if (is_one_instruction) {
    ll_w(rd, rj.base(), rj.offset());
  } else {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    li(scratch, rj.offset());
    add_d(scratch, scratch, rj.base());
    ll_w(rd, scratch, 0);
  }
}

void MacroAssembler::Ll_d(Register rd, const MemOperand& rj) {
  DCHECK(!rj.hasIndexReg());
  bool is_one_instruction = is_int14(rj.offset());
  if (is_one_instruction) {
    ll_d(rd, rj.base(), rj.offset());
  } else {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    li(scratch, rj.offset());
    add_d(scratch, scratch, rj.base());
    ll_d(rd, scratch, 0);
  }
}

void MacroAssembler::Sc_w(Register rd, const MemOperand& rj) {
  DCHECK(!rj.hasIndexReg());
  bool is_one_instruction = is_int14(rj.offset());
  if (is_one_instruction) {
    sc_w(rd, rj.base(), rj.offset());
  } else {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    li(scratch, rj.offset());
    add_d(scratch, scratch, rj.base());
    sc_w(rd, scratch, 0);
  }
}

void MacroAssembler::Sc_d(Register rd, const MemOperand& rj) {
  DCHECK(!rj.hasIndexReg());
  bool is_one_instruction = is_int14(rj.offset());
  if (is_one_instruction) {
    sc_d(rd, rj.base(), rj.offset());
  } else {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    li(scratch, rj.offset());
    add_d(scratch, scratch, rj.base());
    sc_d(rd, scratch, 0);
  }
}

void MacroAssembler::li(Register dst, Handle<HeapObject> value,
                        RelocInfo::Mode rmode, LiFlags mode) {
  // TODO(jgruber,v8:8887): Also consider a root-relative load when generating
  // non-isolate-independent code. In many cases it might be cheaper than
  // embedding the relocatable value.
  if (root_array_available_ && options().isolate_independent_code) {
    IndirectLoadConstant(dst, value);
    return;
  }
  li(dst, Operand(value), mode);
}

void MacroAssembler::li(Register dst, ExternalReference reference,
                        LiFlags mode) {
  if (root_array_available()) {
    if (reference.IsIsolateFieldId()) {
      Add_d(dst, kRootRegister, Operand(reference.offset_from_root_register()));
      return;
    }
    if (options().isolate_independent_code) {
      IndirectLoadExternalReference(dst, reference);
      return;
    }
  }

  // External references should not get created with IDs if
  // `!root_array_available()`.
  CHECK(!reference.IsIsolateFieldId());
  li(dst, Operand(reference), mode);
}

static inline int InstrCountForLiLower32Bit(int64_t value) {
  if (is_int12(static_cast<int32_t>(value)) ||
      is_uint12(static_cast<int32_t>(value)) || !(value & kImm12Mask)) {
    return 1;
  } else {
    return 2;
  }
}

void MacroAssembler::LiLower32BitHelper(Register rd, Operand j) {
  if (is_int12(static_cast<int32_t>(j.immediate()))) {
    addi_d(rd, zero_reg, j.immediate());
  } else if (is_uint12(static_cast<int32_t>(j.immediate()))) {
    ori(rd, zero_reg, j.immediate() & kImm12Mask);
  } else {
    lu12i_w(rd, j.immediate() >> 12 & 0xfffff);
    if (j.immediate() & kImm12Mask) {
      ori(rd, rd, j.immediate() & kImm12Mask);
    }
  }
}

int MacroAssembler::InstrCountForLi64Bit(int64_t value) {
  if (is_int32(value)) {
    return InstrCountForLiLower32Bit(value);
  } else if (is_int52(value)) {
    return InstrCountForLiLower32Bit(value) + 1;
  } else if ((value & 0xffffffffL) == 0) {
    // 32 LSBs (Least Significant Bits) all set to zero.
    uint8_t tzc = base::bits::CountTrailingZeros32(value >> 32);
    uint8_t lzc = base::bits::CountLeadingZeros32(value >> 32);
    if (tzc >= 20) {
      return 1;
    } else if (tzc + lzc > 12) {
      return 2;
    } else {
      return 3;
    }
  } else {
    int64_t imm21 = (value >> 31) & 0x1fffffL;
    if (imm21 != 0x1fffffL && imm21 != 0) {
      return InstrCountForLiLower32Bit(value) + 2;
    } else {
      return InstrCountForLiLower32Bit(value) + 1;
    }
  }
  UNREACHABLE();
  return INT_MAX;
}

// All changes to if...else conditions here must be added to
// InstrCountForLi64Bit as well.
void MacroAssembler::li_optimized(Register rd, Operand j, LiFlags mode) {
  DCHECK(!j.is_reg());
  DCHECK(!MustUseReg(j.rmode()));
  DCHECK(mode == OPTIMIZE_SIZE);
  int64_t imm = j.immediate();
  BlockTrampolinePoolScope block_trampoline_pool(this);
  // Normal load of an immediate value which does not need Relocation Info.
  if (is_int32(imm)) {
    LiLower32BitHelper(rd, j);
  } else if (is_int52(imm)) {
    LiLower32BitHelper(rd, j);
    lu32i_d(rd, imm >> 32 & 0xfffff);
  } else if ((imm & 0xffffffffL) == 0) {
    // 32 LSBs (Least Significant Bits) all set to zero.
    uint8_t tzc = base::bits::CountTrailingZeros32(imm >> 32);
    uint8_t lzc = base::bits::CountLeadingZeros32(imm >> 32);
    if (tzc >= 20) {
      lu52i_d(rd, zero_reg, imm >> 52 & kImm12Mask);
    } else if (tzc + lzc > 12) {
      int32_t mask = (1 << (32 - tzc)) - 1;
      lu12i_w(rd, imm >> (tzc + 32) & mask);
      slli_d(rd, rd, tzc + 20);
    } else {
      xor_(rd, rd, rd);
      lu32i_d(rd, imm >> 32 & 0xfffff);
      lu52i_d(rd, rd, imm >> 52 & kImm12Mask);
    }
  } else {
    int64_t imm21 = (imm >> 31) & 0x1fffffL;
    LiLower32BitHelper(rd, j);
    if (imm21 != 0x1fffffL && imm21 != 0) lu32i_d(rd, imm >> 32 & 0xfffff);
    lu52i_d(rd, rd, imm >> 52 & kImm12Mask);
  }
}

void MacroAssembler::li(Register rd, Operand j, LiFlags mode) {
  DCHECK(!j.is_reg());
  BlockTrampolinePoolScope block_trampoline_pool(this);
  if (!MustUseReg(j.rmode()) && mode == OPTIMIZE_SIZE) {
    li_optimized(rd, j, mode);
  } else if (RelocInfo::IsCompressedEmbeddedObject(j.rmode())) {
    Handle<HeapObject> handle(reinterpret_cast<Address*>(j.immediate()));
    uint32_t immediate = AddEmbeddedObject(handle);
    RecordRelocInfo(j.rmode(), immediate);
    lu12i_w(rd, immediate >> 12 & 0xfffff);
    ori(rd, rd, immediate & kImm12Mask);
  } else if (MustUseReg(j.rmode())) {
    int64_t immediate;
    if (j.IsHeapNumberRequest()) {
      RequestHeapNumber(j.heap_number_request());
      immediate = 0;
    } else if (RelocInfo::IsFullEmbeddedObject(j.rmode())) {
      Handle<HeapObject> handle(reinterpret_cast<Address*>(j.immediate()));
      immediate = AddEmbeddedObject(handle);
    } else {
      immediate = j.immediate();
    }

    RecordRelocInfo(j.rmode(), immediate);
    lu12i_w(rd, immediate >> 12 & 0xfffff);
    ori(rd, rd, immediate & kImm12Mask);
    if (RelocInfo::IsWasmCanonicalSigId(j.rmode())) {
      // wasm_canonical_sig_id is 32-bit value.
      DCHECK(is_int32(immediate));
      return;
    }
    lu32i_d(rd, immediate >> 32 & 0xfffff);
  } else if (mode == ADDRESS_LOAD) {
    // We always need the same number of instructions as we may need to patch
    // this code to load another value which may need all 3 instructions.
    lu12i_w(rd, j.immediate() >> 12 & 0xfffff);
    ori(rd, rd, j.immediate() & kImm12Mask);
    lu32i_d(rd, j.immediate() >> 32 & 0xfffff);
  } else {  // mode == CONSTANT_SIZE - always emit the same instruction
            // sequence.
    lu12i_w(rd, j.immediate() >> 12 & 0xfffff);
    ori(rd, rd, j.immediate() & kImm12Mask);
    lu32i_d(rd, j.immediate() >> 32 & 0xfffff);
    lu52i_d(rd, rd, j.immediate() >> 52 & kImm12Mask);
  }
}

void MacroAssembler::LoadIsolateField(Register dst, IsolateFieldId id) {
  li(dst, ExternalReference::Create(id));
}

void MacroAssembler::MultiPush(RegList regs) {
  int16_t stack_offset = 0;

  for (int16_t i = kNumRegisters - 1; i >= 0; i--) {
    if ((regs.bits() & (1 << i)) != 0) {
      stack_offset -= kSystemPointerSize;
      St_d(ToRegister(i), MemOperand(sp, stack_offset));
    }
  }
  addi_d(sp, sp, stack_offset);
}

void MacroAssembler::MultiPush(RegList regs1, RegList regs2) {
  DCHECK((regs1 & regs2).is_empty());
  int16_t stack_offset = 0;

  for (int16_t i = kNumRegisters - 1; i >= 0; i--) {
    if ((regs1.bits() & (1 << i)) != 0) {
      stack_offset -= kSystemPointerSize;
      St_d(ToRegister(i), MemOperand(sp, stack_offset));
    }
  }
  for (int16_t i = kNumRegisters - 1; i >= 0; i--) {
    if ((regs2.bits() & (1 << i)) != 0) {
      stack_offset -= kSystemPointerSize;
      St_d(ToRegister(i), MemOperand(sp, stack_offset));
    }
  }
  addi_d(sp, sp, stack_offset);
}

void MacroAssembler::MultiPush(RegList regs1, RegList regs2, RegList regs3) {
  DCHECK((regs1 & regs2).is_empty());
  DCHECK((regs1 & regs3).is_empty());
  DCHECK((regs2 & regs3).is_empty());
  int16_t stack_offset = 0;

  for (int16_t i = kNumRegisters - 1; i >= 0; i--) {
    if ((regs1.bits() & (1 << i)) != 0) {
      stack_offset -= kSystemPointerSize;
      St_d(ToRegister(i), MemOperand(sp, stack_offset));
    }
  }
  for (int16_t i = kNumRegisters - 1; i >= 0; i--) {
    if ((regs2.bits() & (1 << i)) != 0) {
      stack_offset -= kSystemPointerSize;
      St_d(ToRegister(i), MemOperand(sp, stack_offset));
    }
  }
  for (int16_t i = kNumRegisters - 1; i >= 0; i--) {
    if ((regs3.bits() & (1 << i)) != 0) {
      stack_offset -= kSystemPointerSize;
      St_d(ToRegister(i), MemOperand(sp, stack_offset));
    }
  }
  addi_d(sp, sp, stack_offset);
}

void MacroAssembler::MultiPop(RegList regs) {
  int16_t stack_offset = 0;

  for (int16_t i = 0; i < kNumRegisters; i++) {
    if ((regs.bits() & (1 << i)) != 0) {
      Ld_d(ToRegister(i), MemOperand(sp, stack_offset));
      stack_offset += kSystemPointerSize;
    }
  }
  addi_d(sp, sp, stack_offset);
}

void MacroAssembler::MultiPop(RegList regs1, RegList regs2) {
  DCHECK((regs1 & regs2).is_empty());
  int16_t stack_offset = 0;

  for (int16_t i = 0; i < kNumRegisters; i++) {
    if ((regs2.bits() & (1 << i)) != 0) {
      Ld_d(ToRegister(i), MemOperand(sp, stack_offset));
      stack_offset += kSystemPointerSize;
    }
  }
  for (int16_t i = 0; i < kNumRegisters; i++) {
    if ((regs1.bits() & (1 << i)) != 0) {
      Ld_d(ToRegister(i), MemOperand(sp, stack_offset));
      stack_offset += kSystemPointerSize;
    }
  }
  addi_d(sp, sp, stack_offset);
}

void MacroAssembler::MultiPop(RegList regs1, RegList regs2, RegList regs3) {
  DCHECK((regs1 & regs2).is_empty());
  DCHECK((regs1 & regs3).is_empty());
  DCHECK((regs2 & regs3).is_empty());
  int16_t stack_offset = 0;

  for (int16_t i = 0; i < kNumRegisters; i++) {
    if ((regs3.bits() & (1 << i)) != 0) {
      Ld_d(ToRegister(i), MemOperand(sp, stack_offset));
      stack_offset += kSystemPointerSize;
    }
  }
  for (int16_t i = 0; i < kNumRegisters; i++) {
    if ((regs2.bits() & (1 << i)) != 0) {
      Ld_d(ToRegister(i), MemOperand(sp, stack_offset));
      stack_offset += kSystemPointerSize;
    }
  }
  for (int16_t i = 0; i < kNumRegisters; i++) {
    if ((regs1.bits() & (1 << i)) != 0) {
      Ld_d(ToRegister(i), MemOperand(sp, stack_offset));
      stack_offset += kSystemPointerSize;
    }
  }
  addi_d(sp, sp, stack_offset);
}

void MacroAssembler::MultiPushFPU(DoubleRegList regs) {
  int16_t num_to_push = regs.Count();
  int16_t stack_offset = num_to_push * kDoubleSize;

  Sub_d(sp, sp, Operand(stack_offset));
  for (int16_t i = kNumRegisters - 1; i >= 0; i--) {
    if ((regs.bits() & (1 << i)) != 0) {
      stack_offset -= kDoubleSize;
      Fst_d(FPURegister::from_code(i), MemOperand(sp, stack_offset));
    }
  }
}

void MacroAssembler::MultiPopFPU(DoubleRegList regs) {
  int16_t stack_offset = 0;

  for (int16_t i = 0; i < kNumRegisters; i++) {
    if ((regs.bits() & (1 << i)) != 0) {
      Fld_d(FPURegister::from_code(i), MemOperand(sp, stack_offset));
      stack_offset += kDoubleSize;
    }
  }
  addi_d(sp, sp, stack_offset);
}

void MacroAssembler::Bstrpick_w(Register rk, Register rj, uint16_t msbw,
                                uint16_t lsbw) {
  DCHECK_LT(lsbw, msbw);
  DCHECK_LT(lsbw, 32);
  DCHECK_LT(msbw, 32);
  bstrpick_w(rk, rj, msbw, lsbw);
}

void MacroAssembler::Bstrpick_d(Register rk, Register rj, uint16_t msbw,
                                uint16_t lsbw) {
  DCHECK_LT(lsbw, msbw);
  DCHECK_LT(lsbw, 64);
  DCHECK_LT(msbw, 64);
  bstrpick_d(rk, rj, msbw, lsbw);
}

void MacroAssembler::Neg_s(FPURegister fd, FPURegister fj) { fneg_s(fd, fj); }

void MacroAssembler::Neg_d(FPURegister fd, FPURegister fj) { fneg_d(fd, fj); }

void MacroAssembler::Ffint_d_uw(FPURegister fd, FPURegister fj) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  movfr2gr_s(t8, fj);
  Ffint_d_uw(fd, t8);
}

void MacroAssembler::Ffint_d_uw(FPURegister fd, Register rj) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  DCHECK(rj != t7);

  Bstrpick_d(t7, rj, 31, 0);
  movgr2fr_d(fd, t7);
  ffint_d_l(fd, fd);
}

void MacroAssembler::Ffint_d_ul(FPURegister fd, FPURegister fj) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  movfr2gr_d(t8, fj);
  Ffint_d_ul(fd, t8);
}

void MacroAssembler::Ffint_d_ul(FPURegister fd, Register rj) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  DCHECK(rj != t7);

  Label msb_clear, conversion_done;

  Branch(&msb_clear, ge, rj, Operand(zero_reg));

  // Rj >= 2^63
  andi(t7, rj, 1);
  srli_d(rj, rj, 1);
  or_(t7, t7, rj);
  movgr2fr_d(fd, t7);
  ffint_d_l(fd, fd);
  fadd_d(fd, fd, fd);
  Branch(&conversion_done);

  bind(&msb_clear);
  // Rs < 2^63, we can do simple conversion.
  movgr2fr_d(fd, rj);
  ffint_d_l(fd, fd);

  bind(&conversion_done);
}

void MacroAssembler::Ffint_s_uw(FPURegister fd, FPURegister fj) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  movfr2gr_d(t8, fj);
  Ffint_s_uw(fd, t8);
}

void MacroAssembler::Ffint_s_uw(FPURegister fd, Register rj) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  DCHECK(rj != t7);

  bstrpick_d(t7, rj, 31, 0);
  movgr2fr_d(fd, t7);
  ffint_s_l(fd, fd);
}

void MacroAssembler::Ffint_s_ul(FPURegister fd, FPURegister fj) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  movfr2gr_d(t8, fj);
  Ffint_s_ul(fd, t8);
}

void MacroAssembler::Ffint_s_ul(FPURegister fd, Register rj) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  DCHECK(rj != t7);

  Label positive, conversion_done;

  Branch(&positive, ge, rj, Operand(zero_reg));

  // Rs >= 2^31.
  andi(t7, rj, 1);
  srli_d(rj, rj, 1);
  or_(t7, t7, rj);
  movgr2fr_d(fd, t7);
  ffint_s_l(fd, fd);
  fadd_s(fd, fd, fd);
  Branch(&conversion_done);

  bind(&positive);
  // Rs < 2^31, we can do simple conversion.
  movgr2fr_d(fd, rj);
  ffint_s_l(fd, fd);

  bind(&conversion_done);
}

void MacroAssembler::Ftintrne_l_d(FPURegister fd, FPURegister fj) {
  ftintrne_l_d(fd, fj);
}

void MacroAssembler::Ftintrm_l_d(FPURegister fd, FPURegister fj) {
  ftintrm_l_d(fd, fj);
}

void MacroAssembler::Ftintrp_l_d(FPURegister fd, FPURegister fj) {
  ftintrp_l_d(fd, fj);
}

void MacroAssembler::Ftintrz_l_d(FPURegister fd, FPURegister fj) {
  ftintrz_l_d(fd, fj);
}

void MacroAssembler::Ftintrz_l_ud(FPURegister fd, FPURegister fj,
                                  FPURegister scratch) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  // Load to GPR.
  movfr2gr_d(t8, fj);
  // Reset sign bit.
  {
    UseScratchRegisterScope temps(this);
    Register scratch1 = temps.Acquire();
    li(scratch1, 0x7FFFFFFFFFFFFFFFl);
    and_(t8, t8, scratch1);
  }
  movgr2fr_d(scratch, t8);
  Ftintrz_l_d(fd, scratch);
}

void MacroAssembler::Ftintrz_uw_d(FPURegister fd, FPURegister fj,
                                  FPURegister scratch) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Ftintrz_uw_d(t8, fj, scratch);
  movgr2fr_w(fd, t8);
}

void MacroAssembler::Ftintrz_uw_s(FPURegister fd, FPURegister fj,
                                  FPURegister scratch) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Ftintrz_uw_s(t8, fj, scratch);
  movgr2fr_w(fd, t8);
}

void MacroAssembler::Ftintrz_ul_d(FPURegister fd, FPURegister fj,
                                  FPURegister scratch, Register result) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Ftintrz_ul_d(t8, fj, scratch, result);
  movgr2fr_d(fd, t8);
}

void MacroAssembler::Ftintrz_ul_s(FPURegister fd, FPURegister fj,
                                  FPURegister scratch, Register result) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Ftintrz_ul_s(t8, fj, scratch, result);
  movgr2fr_d(fd, t8);
}

void MacroAssembler::Ftintrz_w_d(FPURegister fd, FPURegister fj) {
  ftintrz_w_d(fd, fj);
}

void MacroAssembler::Ftintrne_w_d(FPURegister fd, FPURegister fj) {
  ftintrne_w_d(fd, fj);
}

void MacroAssembler::Ftintrm_w_d(FPURegister fd, FPURegister fj) {
  ftintrm_w_d(fd, fj);
}

void MacroAssembler::Ftintrp_w_d(FPURegister fd, FPURegister fj) {
  ftintrp_w_d(fd, fj);
}

void MacroAssembler::Ftintrz_uw_d(Register rd, FPURegister fj,
                                  FPURegister scratch) {
  DCHECK(fj != scratch);
  DCHECK(rd != t7);

  {
    // Load 2^32 into scratch as its float representation.
    UseScratchRegisterScope temps(this);
    Register scratch1 = temps.Acquire();
    li(scratch1, 0x41F0000000000000);
    movgr2fr_d(scratch, scratch1);
  }
  // Test if scratch > fd.
  // If fd < 2^32 we can convert it normally.
  Label simple_convert;
  CompareF64(fj, scratch, CULT);
  BranchTrueShortF(&simple_convert);

  // If fd > 2^32, the result should be UINT_32_MAX;
  Add_w(rd, zero_reg, -1);

  Label done;
  Branch(&done);
  // Simple conversion.
  bind(&simple_convert);
  // Double -> Int64 -> Uint32;
  ftintrz_l_d(scratch, fj);
  movfr2gr_s(rd, scratch);

  bind(&done);
}

void MacroAssembler::Ftintrz_uw_s(Register rd, FPURegister fj,
                                  FPURegister scratch) {
  DCHECK(fj != scratch);
  DCHECK(rd != t7);
  {
    // Load 2^32 into scratch as its float representation.
    UseScratchRegisterScope temps(this);
    Register scratch1 = temps.Acquire();
    li(scratch1, 0x4F800000);
    movgr2fr_w(scratch, scratch1);
  }
  // Test if scratch > fs.
  // If fs < 2^32 we can convert it normally.
  Label simple_convert;
  CompareF32(fj, scratch, CULT);
  BranchTrueShortF(&simple_convert);

  // If fd > 2^32, the result should be UINT_32_MAX;
  Add_w(rd, zero_reg, -1);

  Label done;
  Branch(&done);
  // Simple conversion.
  bind(&simple_convert);
  // Float -> Int64 -> Uint32;
  ftintrz_l_s(scratch, fj);
  movfr2gr_s(rd, scratch);

  bind(&done);
}

void MacroAssembler::Ftintrz_ul_d(Register rd, FPURegister fj,
                                  FPURegister scratch, Register result) {
  DCHECK(fj != scratch);
  DCHECK(result.is_valid() ? !AreAliased(rd, result, t7) : !AreAliased(rd, t7));

  Label simple_convert, done, fail;
  if (result.is_valid()) {
    mov(result, zero_reg);
    Move(scratch, -1.0);
    // If fd =< -1 or unordered, then the conversion fails.
    CompareF64(fj, scratch, CULE);
    BranchTrueShortF(&fail);
  }

  // Load 2^63 into scratch as its double representation.
  li(t7, 0x43E0000000000000);
  movgr2fr_d(scratch, t7);

  // Test if scratch > fs.
  // If fs < 2^63 or unordered we can convert it normally.
  CompareF64(fj, scratch, CULT);
  BranchTrueShortF(&simple_convert);

  // First we subtract 2^63 from fs, then trunc it to rd
  // and add 2^63 to rd.
  fsub_d(scratch, fj, scratch);
  ftintrz_l_d(scratch, scratch);
  movfr2gr_d(rd, scratch);
  Or(rd, rd, Operand(1UL << 63));
  Branch(&done);

  // Simple conversion.
  bind(&simple_convert);
  ftintrz_l_d(scratch, fj);
  movfr2gr_d(rd, scratch);

  bind(&done);
  if (result.is_valid()) {
    // Conversion is failed if the result is negative.
    {
      UseScratchRegisterScope temps(this);
      Register scratch1 = temps.Acquire();
      addi_d(scratch1, zero_reg, -1);
      srli_d(scratch1, scratch1, 1);  // Load 2^62.
      movfr2gr_d(result, scratch);
      xor_(result, result, scratch1);
    }
    Slt(result, zero_reg, result);
  }

  bind(&fail);
}

void MacroAssembler::Ftintrz_ul_s(Register rd, FPURegister fj,
                                  FPURegister scratch, Register result) {
  DCHECK(fj != scratch);
  DCHECK(result.is_valid() ? !AreAliased(rd, result, t7) : !AreAliased(rd, t7));

  Label simple_convert, done, fail;
  if (result.is_valid()) {
    mov(result, zero_reg);
    Move(scratch, -1.0f);
    // If fd =< -1 or unordered, then the conversion fails.
    CompareF32(fj, scratch, CULE);
    BranchTrueShortF(&fail);
  }

  {
    // Load 2^63 into scratch as its float representation.
    UseScratchRegisterScope temps(this);
    Register scratch1 = temps.Acquire();
    li(scratch1, 0x5F000000);
    movgr2fr_w(scratch, scratch1);
  }

  // Test if scratch > fs.
  // If fs < 2^63 or unordered, we can convert it normally.
  CompareF32(fj, scratch, CULT);
  BranchTrueShortF(&simple_convert);

  // First we subtract 2^63 from fs, then trunc it to rd
  // and add 2^63 to rd.
  fsub_s(scratch, fj, scratch);
  ftintrz_l_s(scratch, scratch);
  movfr2gr_d(rd, scratch);
  Or(rd, rd, Operand(1UL << 63));
  Branch(&done);

  // Simple conversion.
  bind(&simple_convert);
  ftintrz_l_s(scratch, fj);
  movfr2gr_d(rd, scratch);

  bind(&done);
  if (result.is_valid()) {
    // Conversion is failed if the result is negative or unordered.
    {
      UseScratchRegisterScope temps(this);
      Register scratch1 = temps.Acquire();
      addi_d(scratch1, zero_reg, -1);
      srli_d(scratch1, scratch1, 1);  // Load 2^62.
      movfr2gr_d(result, scratch);
      xor_(result, result, scratch1);
    }
    Slt(result, zero_reg, result);
  }

  bind(&fail);
}

void MacroAssembler::RoundDouble(FPURegister dst, FPURegister src,
                                 FPURoundingMode mode) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register scratch = t8;
  movfcsr2gr(scratch);
  li(t7, Operand(mode));
  movgr2fcsr(t7);
  frint_d(dst, src);
  movgr2fcsr(scratch);
}

void MacroAssembler::Floor_d(FPURegister dst, FPURegister src) {
  RoundDouble(dst, src, mode_floor);
}

void MacroAssembler::Ceil_d(FPURegister dst, FPURegister src) {
  RoundDouble(dst, src, mode_ceil);
}

void MacroAssembler::Trunc_d(FPURegister dst, FPURegister src) {
  RoundDouble(dst, src, mode_trunc);
}

void MacroAssembler::Round_d(FPURegister dst, FPURegister src) {
  RoundDouble(dst, src, mode_round);
}

void MacroAssembler::RoundFloat(FPURegister dst, FPURegister src,
                                FPURoundingMode mode) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register scratch = t8;
  movfcsr2gr(scratch);
  li(t7, Operand(mode));
  movgr2fcsr(t7);
  frint_s(dst, src);
  movgr2fcsr(scratch);
}

void MacroAssembler::Floor_s(FPURegister dst, FPURegister src) {
  RoundFloat(dst, src, mode_floor);
}

void MacroAssembler::Ceil_s(FPURegister dst, FPURegister src) {
  RoundFloat(dst, src, mode_ceil);
}

void MacroAssembler::Trunc_s(FPURegister dst, FPURegister src) {
  RoundFloat(dst, src, mode_trunc);
}

void MacroAssembler::Round_s(FPURegister dst, FPURegister src) {
  RoundFloat(dst, src, mode_round);
}

void MacroAssembler::CompareF(FPURegister cmp1, FPURegister cmp2,
                              FPUCondition cc, CFRegister cd, bool f32) {
  if (f32) {
    fcmp_cond_s(cc, cmp1, cmp2, cd);
  } else {
    fcmp
"""


```