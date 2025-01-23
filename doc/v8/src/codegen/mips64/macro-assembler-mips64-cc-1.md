Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/codegen/mips64/macro-assembler-mips64.cc`.

Here's a breakdown of the thought process to achieve the desired summary:

1. **Identify the Core Purpose:** The file name `macro-assembler-mips64.cc` strongly suggests that this code deals with generating MIPS64 assembly instructions. The "macro" part implies higher-level abstractions over raw assembly.

2. **Analyze Function Signatures and Names:** Scan through the function definitions. Notice patterns in naming:
    * Functions starting with uppercase letters (e.g., `Ulwu`, `Usw`, `Ulh`) often represent instructions, possibly with variations like handling unaligned access ('U').
    * Functions with lowercase mnemonics (e.g., `lb`, `lbu`, `sb`) are likely the underlying assembly instructions themselves.
    * Functions involving `FPURegister` indicate floating-point operations.
    * Functions like `MultiPush`, `MultiPop` suggest stack manipulation.
    * Functions with names like `li`, `li_optimized` are likely related to loading immediate values.
    * Functions with `Ext`, `Dext`, `Ins`, `Dins` suggest bit manipulation.
    * Functions related to `Neg_s` and `Neg_d` point to negation operations on floating-point numbers.

3. **Group Functions by Functionality:**  Based on the names and signatures, group related functions:
    * **Memory Access (Unaligned and Aligned):** `Ulwu`, `Usw`, `Ulh`, `Ulhu`, `Ush`, `Uld`, `Usd`, `Ulwc1`, `Uswc1`, `Uldc1`, `Usdc1`, `Lb`, `Lbu`, `Sb`, `Lh`, `Lhu`, `Sh`, `Lw`, `Lwu`, `Sw`, `Ld`, `Sd`, `Lwc1`, `Swc1`, `Ldc1`, `Sdc1`, `Ll`, `Lld`, `Sc`, `Scd`.
    * **Loading Constants/Immediate Values:** `li`, `li_optimized`, `LoadIsolateField`.
    * **Stack Operations:** `MultiPush`, `MultiPop`, `MultiPushFPU`, `MultiPopFPU`, `MultiPushMSA`, `MultiPopMSA`.
    * **Bit Manipulation:** `Ext`, `Dext`, `Ins`, `Dins`, `ExtractBits`, `InsertBits`.
    * **Floating-Point Negation:** `Neg_s`, `Neg_d`.
    * **Floating-Point Conversion:** `Cvt_d_uw`.

4. **Infer the Purpose of Each Group:**
    * **Memory Access:** Provides methods for loading and storing data of different sizes (bytes, half-words, words, double-words) from memory, including handling unaligned accesses and variations based on MIPS architecture revisions (r2 vs. r6).
    * **Loading Constants:** Offers ways to load immediate values (integers, addresses, handles) into registers, with optimizations for size and handling of relocatable values.
    * **Stack Operations:** Implements efficient methods to push and pop multiple registers onto and from the stack, for both general-purpose and floating-point registers.
    * **Bit Manipulation:** Provides functions to extract, insert, and manipulate bits within registers.
    * **Floating-Point Negation:** Implements floating-point negation, considering the nuances of NaN handling on different MIPS architectures.
    * **Floating-Point Conversion:** Handles conversion between unsigned word and double-precision floating-point values.

5. **Address the Specific Questions:**
    * **Functionality:**  Synthesize the grouped functionalities into a concise description.
    * **Torque:** The provided snippet is C++, not Torque, as it doesn't end with `.tq`.
    * **JavaScript Relation:**  These low-level operations are fundamental to how V8 executes JavaScript. Provide examples like accessing object properties (memory loads) and performing arithmetic (immediate loads, bit manipulation, floating-point operations).
    * **Code Logic (Example):** Choose a relatively simple function like `Ulwu` and provide a hypothetical scenario to illustrate its behavior.
    * **Common Programming Errors:**  Relate common errors like unaligned memory access to the functionality of the unaligned access instructions.

6. **Structure the Summary:** Organize the findings logically, starting with the overall purpose and then detailing the specific functionalities, addressing the user's questions in order.

7. **Refine and Edit:**  Review the summary for clarity, accuracy, and completeness. Ensure it directly answers the user's prompt and is easy to understand. For example, initially, I might have just listed the function names, but then realized the need to group them and explain the *purpose* of each group. Also, ensure consistent terminology (e.g., always referring to "MIPS64").

This step-by-step process, focusing on understanding the code's structure, naming conventions, and relating it to the broader context of a macro-assembler, allows for a comprehensive and accurate summary of the provided code snippet.
好的，我们来归纳一下这段代码的功能。

这段代码是 `v8/src/codegen/mips64/macro-assembler-mips64.cc` 文件的一部分，它主要定义了 `MacroAssembler` 类的一些成员函数，用于生成 MIPS64 架构的机器码指令。  这些函数是对底层 MIPS64 指令的封装，提供了更高级别的抽象，方便 V8 引擎的代码生成器使用。

**主要功能归纳:**

1. **非对齐内存访问指令的封装 (Unaligned Memory Access):**
   - 提供了 `Ulwu`, `Usw`, `Ulh`, `Ulhu`, `Ush`, `Uld`, `Usd`, `Ulwc1`, `Uswc1`, `Uldc1`, `Usdc1` 等函数，用于处理非对齐的内存访问。这些函数会根据 MIPS64 的架构变体 (R6 或 R2) 生成相应的指令序列来完成非对齐的读写操作。
   - 例如，在 MIPS64r2 架构上，读取一个非对齐的字（32位），需要使用 `lwr` 和 `lwl` 两条指令组合实现。

2. **基本的内存访问指令封装 (Aligned Memory Access):**
   - 封装了 MIPS64 的基本加载和存储指令，例如 `Lb`, `Lbu`, `Sb`, `Lh`, `Lhu`, `Sh`, `Lw`, `Lwu`, `Sw`, `Ld`, `Sd`, `Lwc1`, `Swc1`, `Ldc1`, `Sdc1`。
   - 这些函数内部会调用 `AdjustBaseAndOffset` 来处理内存操作数的基址寄存器和偏移量。

3. **原子内存操作指令封装 (Atomic Memory Access):**
   - 提供了 `Ll`, `Lld`, `Sc`, `Scd` 等函数，用于生成加载链接（Load-Linked）和条件存储（Store-Conditional）指令，用于实现原子操作。

4. **加载立即数 (Load Immediate):**
   - 提供了多个 `li` 函数的重载版本，用于将立即数加载到寄存器中。这些函数可以加载：
     - 立即数常量 (`int64_t`)
     - HeapObject 的句柄 (`Handle<HeapObject>`)
     - 外部引用 (`ExternalReference`)
   - `li_optimized` 函数提供了一种优化的加载立即数的方法，可以根据立即数的值选择更短的指令序列。

5. **栈操作 (Stack Operations):**
   - 提供了 `MultiPush` 和 `MultiPop` 函数，用于批量压入和弹出多个通用寄存器。
   - 提供了 `MultiPushFPU` 和 `MultiPopFPU` 函数，用于批量压入和弹出多个浮点寄存器。
   - 提供了 `MultiPushMSA` 和 `MultiPopMSA` 函数，用于批量压入和弹出 MSA (MIPS SIMD Architecture) 寄存器。

6. **位操作 (Bit Manipulation):**
   - 提供了 `Ext`, `Dext`, `Ins`, `Dins`, `ExtractBits`, `InsertBits` 等函数，用于从寄存器中提取位域和插入位域。

7. **浮点数操作 (Floating-Point Operations):**
   - 提供了 `Neg_s` 和 `Neg_d` 函数，用于对单精度和双精度浮点数取反，并考虑了 NaN 值的处理。
   - 提供了 `Cvt_d_uw` 函数，用于将无符号字转换为双精度浮点数。

**关于代码逻辑推理的例子 (以 `Ulwu` 为例):**

**假设输入:**
- `rd` 寄存器为 `t0`
- `rs` MemOperand 代表内存地址 `[s0 + 4]` (其中 `s0` 的值为 0x1000)

**输出 (取决于 MIPS64 架构变体):**

- **如果 `kArchVariant == kMips64r6`:**
  - 会生成一条 `lwu t0, 4(s0)` 指令，直接进行非对齐的无符号字加载。

- **如果 `kArchVariant == kMips64r2`:**
  - 会生成以下指令序列:
    ```assembly
    lwl scratch, 0(s0)  // scratch 是一个临时寄存器
    lwr scratch, 7(s0)
    dext t0, scratch, 0, 32
    ```
    - `lwl` (load word left): 从 `s0` 地址加载部分字到 `scratch` 的高位。
    - `lwr` (load word right): 从 `s0 + 7` 地址加载部分字到 `scratch` 的低位。
    - `dext`: 从 `scratch` 寄存器中提取 0 到 31 位（一个字）并放入 `t0`。

**关于用户常见的编程错误举例:**

涉及非对齐内存访问时，常见的编程错误是 **直接使用普通的加载/存储指令 (如 `lw`, `sw`) 来访问非对齐的地址**。在某些架构上，这会导致硬件异常或未定义的行为。

**JavaScript 示例 (与功能相关):**

尽管这段代码是 C++，但它服务于 V8 引擎执行 JavaScript。 例如，当 JavaScript 代码访问对象的属性时：

```javascript
const obj = { a: 1 };
const value = obj.a;
```

V8 引擎在执行这段代码时，可能需要生成类似 `Lw` (如果属性值是整数) 或 `Ldc1` (如果属性值是浮点数) 这样的指令，从对象在内存中的位置加载属性 `a` 的值。

如果 JavaScript 中使用了 `DataView` 或 `ArrayBuffer` 等 API 来进行底层的内存操作，并且访问的地址是非对齐的，那么 V8 引擎就会使用像 `Ulwu` 或 `Usw` 这样的指令来安全地进行访问。

**总结这段代码的功能 (第 2 部分):**

这段代码继续扩展了 `MacroAssembler` 类的功能，主要集中在以下方面：

- **提供了处理不同大小和对齐方式的内存加载和存储操作的指令封装，包括原子操作。**
- **实现了加载各种类型的立即数到寄存器的功能，并针对代码大小进行了优化。**
- **支持批量操作寄存器（压栈和出栈），提高了代码生成的效率。**
- **提供了基本的位操作和浮点数操作的指令封装。**

总体而言，这部分代码为 V8 引擎在 MIPS64 架构上生成高效且正确的机器码指令提供了重要的基础设施。它屏蔽了底层硬件的复杂性，使得代码生成器可以使用更高级别的接口来完成任务.

### 提示词
```
这是目录为v8/src/codegen/mips64/macro-assembler-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/mips64/macro-assembler-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
tchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      lwr(scratch, MemOperand(rs.rm(), rs.offset() + kMipsLwrOffset));
      lwl(scratch, MemOperand(rs.rm(), rs.offset() + kMipsLwlOffset));
      mov(rd, scratch);
    }
  }
}

void MacroAssembler::Ulwu(Register rd, const MemOperand& rs) {
  if (kArchVariant == kMips64r6) {
    Lwu(rd, rs);
  } else {
    DCHECK_EQ(kArchVariant, kMips64r2);
    Ulw(rd, rs);
    Dext(rd, rd, 0, 32);
  }
}

void MacroAssembler::Usw(Register rd, const MemOperand& rs) {
  DCHECK(rd != at);
  DCHECK(rs.rm() != at);
  DCHECK(rd != rs.rm());
  if (kArchVariant == kMips64r6) {
    Sw(rd, rs);
  } else {
    DCHECK_EQ(kArchVariant, kMips64r2);
    DCHECK(kMipsSwrOffset <= 3 && kMipsSwlOffset <= 3);
    MemOperand source = rs;
    // Adjust offset for two accesses and check if offset + 3 fits into int16_t.
    AdjustBaseAndOffset(&source, OffsetAccessType::TWO_ACCESSES, 3);
    swr(rd, MemOperand(source.rm(), source.offset() + kMipsSwrOffset));
    swl(rd, MemOperand(source.rm(), source.offset() + kMipsSwlOffset));
  }
}

void MacroAssembler::Ulh(Register rd, const MemOperand& rs) {
  DCHECK(rd != at);
  DCHECK(rs.rm() != at);
  if (kArchVariant == kMips64r6) {
    Lh(rd, rs);
  } else {
    DCHECK_EQ(kArchVariant, kMips64r2);
    MemOperand source = rs;
    // Adjust offset for two accesses and check if offset + 1 fits into int16_t.
    AdjustBaseAndOffset(&source, OffsetAccessType::TWO_ACCESSES, 1);
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    if (source.rm() == scratch) {
#if defined(V8_TARGET_LITTLE_ENDIAN)
      Lb(rd, MemOperand(source.rm(), source.offset() + 1));
      Lbu(scratch, source);
#elif defined(V8_TARGET_BIG_ENDIAN)
      Lb(rd, source);
      Lbu(scratch, MemOperand(source.rm(), source.offset() + 1));
#endif
    } else {
#if defined(V8_TARGET_LITTLE_ENDIAN)
      Lbu(scratch, source);
      Lb(rd, MemOperand(source.rm(), source.offset() + 1));
#elif defined(V8_TARGET_BIG_ENDIAN)
      Lbu(scratch, MemOperand(source.rm(), source.offset() + 1));
      Lb(rd, source);
#endif
    }
    dsll(rd, rd, 8);
    or_(rd, rd, scratch);
  }
}

void MacroAssembler::Ulhu(Register rd, const MemOperand& rs) {
  DCHECK(rd != at);
  DCHECK(rs.rm() != at);
  if (kArchVariant == kMips64r6) {
    Lhu(rd, rs);
  } else {
    DCHECK_EQ(kArchVariant, kMips64r2);
    MemOperand source = rs;
    // Adjust offset for two accesses and check if offset + 1 fits into int16_t.
    AdjustBaseAndOffset(&source, OffsetAccessType::TWO_ACCESSES, 1);
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    if (source.rm() == scratch) {
#if defined(V8_TARGET_LITTLE_ENDIAN)
      Lbu(rd, MemOperand(source.rm(), source.offset() + 1));
      Lbu(scratch, source);
#elif defined(V8_TARGET_BIG_ENDIAN)
      Lbu(rd, source);
      Lbu(scratch, MemOperand(source.rm(), source.offset() + 1));
#endif
    } else {
#if defined(V8_TARGET_LITTLE_ENDIAN)
      Lbu(scratch, source);
      Lbu(rd, MemOperand(source.rm(), source.offset() + 1));
#elif defined(V8_TARGET_BIG_ENDIAN)
      Lbu(scratch, MemOperand(source.rm(), source.offset() + 1));
      Lbu(rd, source);
#endif
    }
    dsll(rd, rd, 8);
    or_(rd, rd, scratch);
  }
}

void MacroAssembler::Ush(Register rd, const MemOperand& rs, Register scratch) {
  DCHECK(rd != at);
  DCHECK(rs.rm() != at);
  DCHECK(rs.rm() != scratch);
  DCHECK(scratch != at);
  if (kArchVariant == kMips64r6) {
    Sh(rd, rs);
  } else {
    DCHECK_EQ(kArchVariant, kMips64r2);
    MemOperand source = rs;
    // Adjust offset for two accesses and check if offset + 1 fits into int16_t.
    AdjustBaseAndOffset(&source, OffsetAccessType::TWO_ACCESSES, 1);

    if (scratch != rd) {
      mov(scratch, rd);
    }

#if defined(V8_TARGET_LITTLE_ENDIAN)
    Sb(scratch, source);
    srl(scratch, scratch, 8);
    Sb(scratch, MemOperand(source.rm(), source.offset() + 1));
#elif defined(V8_TARGET_BIG_ENDIAN)
    Sb(scratch, MemOperand(source.rm(), source.offset() + 1));
    srl(scratch, scratch, 8);
    Sb(scratch, source);
#endif
  }
}

void MacroAssembler::Uld(Register rd, const MemOperand& rs) {
  DCHECK(rd != at);
  DCHECK(rs.rm() != at);
  if (kArchVariant == kMips64r6) {
    Ld(rd, rs);
  } else {
    DCHECK_EQ(kArchVariant, kMips64r2);
    DCHECK(kMipsLdrOffset <= 7 && kMipsLdlOffset <= 7);
    MemOperand source = rs;
    // Adjust offset for two accesses and check if offset + 7 fits into int16_t.
    AdjustBaseAndOffset(&source, OffsetAccessType::TWO_ACCESSES, 7);
    if (rd != source.rm()) {
      ldr(rd, MemOperand(source.rm(), source.offset() + kMipsLdrOffset));
      ldl(rd, MemOperand(source.rm(), source.offset() + kMipsLdlOffset));
    } else {
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      ldr(scratch, MemOperand(rs.rm(), rs.offset() + kMipsLdrOffset));
      ldl(scratch, MemOperand(rs.rm(), rs.offset() + kMipsLdlOffset));
      mov(rd, scratch);
    }
  }
}

// Load consequent 32-bit word pair in 64-bit reg. and put first word in low
// bits,
// second word in high bits.
void MacroAssembler::LoadWordPair(Register rd, const MemOperand& rs,
                                  Register scratch) {
  Lwu(rd, rs);
  Lw(scratch, MemOperand(rs.rm(), rs.offset() + kPointerSize / 2));
  dsll32(scratch, scratch, 0);
  Daddu(rd, rd, scratch);
}

void MacroAssembler::Usd(Register rd, const MemOperand& rs) {
  DCHECK(rd != at);
  DCHECK(rs.rm() != at);
  if (kArchVariant == kMips64r6) {
    Sd(rd, rs);
  } else {
    DCHECK_EQ(kArchVariant, kMips64r2);
    DCHECK(kMipsSdrOffset <= 7 && kMipsSdlOffset <= 7);
    MemOperand source = rs;
    // Adjust offset for two accesses and check if offset + 7 fits into int16_t.
    AdjustBaseAndOffset(&source, OffsetAccessType::TWO_ACCESSES, 7);
    sdr(rd, MemOperand(source.rm(), source.offset() + kMipsSdrOffset));
    sdl(rd, MemOperand(source.rm(), source.offset() + kMipsSdlOffset));
  }
}

// Do 64-bit store as two consequent 32-bit stores to unaligned address.
void MacroAssembler::StoreWordPair(Register rd, const MemOperand& rs,
                                   Register scratch) {
  Sw(rd, rs);
  dsrl32(scratch, rd, 0);
  Sw(scratch, MemOperand(rs.rm(), rs.offset() + kPointerSize / 2));
}

void MacroAssembler::Ulwc1(FPURegister fd, const MemOperand& rs,
                           Register scratch) {
  if (kArchVariant == kMips64r6) {
    Lwc1(fd, rs);
  } else {
    DCHECK_EQ(kArchVariant, kMips64r2);
    Ulw(scratch, rs);
    mtc1(scratch, fd);
  }
}

void MacroAssembler::Uswc1(FPURegister fd, const MemOperand& rs,
                           Register scratch) {
  if (kArchVariant == kMips64r6) {
    Swc1(fd, rs);
  } else {
    DCHECK_EQ(kArchVariant, kMips64r2);
    mfc1(scratch, fd);
    Usw(scratch, rs);
  }
}

void MacroAssembler::Uldc1(FPURegister fd, const MemOperand& rs,
                           Register scratch) {
  DCHECK(scratch != at);
  if (kArchVariant == kMips64r6) {
    Ldc1(fd, rs);
  } else {
    DCHECK_EQ(kArchVariant, kMips64r2);
    Uld(scratch, rs);
    dmtc1(scratch, fd);
  }
}

void MacroAssembler::Usdc1(FPURegister fd, const MemOperand& rs,
                           Register scratch) {
  DCHECK(scratch != at);
  if (kArchVariant == kMips64r6) {
    Sdc1(fd, rs);
  } else {
    DCHECK_EQ(kArchVariant, kMips64r2);
    dmfc1(scratch, fd);
    Usd(scratch, rs);
  }
}

void MacroAssembler::Lb(Register rd, const MemOperand& rs) {
  MemOperand source = rs;
  AdjustBaseAndOffset(&source);
  lb(rd, source);
}

void MacroAssembler::Lbu(Register rd, const MemOperand& rs) {
  MemOperand source = rs;
  AdjustBaseAndOffset(&source);
  lbu(rd, source);
}

void MacroAssembler::Sb(Register rd, const MemOperand& rs) {
  MemOperand source = rs;
  AdjustBaseAndOffset(&source);
  sb(rd, source);
}

void MacroAssembler::Lh(Register rd, const MemOperand& rs) {
  MemOperand source = rs;
  AdjustBaseAndOffset(&source);
  lh(rd, source);
}

void MacroAssembler::Lhu(Register rd, const MemOperand& rs) {
  MemOperand source = rs;
  AdjustBaseAndOffset(&source);
  lhu(rd, source);
}

void MacroAssembler::Sh(Register rd, const MemOperand& rs) {
  MemOperand source = rs;
  AdjustBaseAndOffset(&source);
  sh(rd, source);
}

void MacroAssembler::Lw(Register rd, const MemOperand& rs) {
  MemOperand source = rs;
  AdjustBaseAndOffset(&source);
  lw(rd, source);
}

void MacroAssembler::Lwu(Register rd, const MemOperand& rs) {
  MemOperand source = rs;
  AdjustBaseAndOffset(&source);
  lwu(rd, source);
}

void MacroAssembler::Sw(Register rd, const MemOperand& rs) {
  MemOperand source = rs;
  AdjustBaseAndOffset(&source);
  sw(rd, source);
}

void MacroAssembler::Ld(Register rd, const MemOperand& rs) {
  MemOperand source = rs;
  AdjustBaseAndOffset(&source);
  ld(rd, source);
}

void MacroAssembler::Sd(Register rd, const MemOperand& rs) {
  MemOperand source = rs;
  AdjustBaseAndOffset(&source);
  sd(rd, source);
}

void MacroAssembler::Lwc1(FPURegister fd, const MemOperand& src) {
  MemOperand tmp = src;
  AdjustBaseAndOffset(&tmp);
  lwc1(fd, tmp);
}

void MacroAssembler::Swc1(FPURegister fs, const MemOperand& src) {
  MemOperand tmp = src;
  AdjustBaseAndOffset(&tmp);
  swc1(fs, tmp);
}

void MacroAssembler::Ldc1(FPURegister fd, const MemOperand& src) {
  MemOperand tmp = src;
  AdjustBaseAndOffset(&tmp);
  ldc1(fd, tmp);
}

void MacroAssembler::Sdc1(FPURegister fs, const MemOperand& src) {
  MemOperand tmp = src;
  AdjustBaseAndOffset(&tmp);
  sdc1(fs, tmp);
}

void MacroAssembler::Ll(Register rd, const MemOperand& rs) {
  bool is_one_instruction = (kArchVariant == kMips64r6) ? is_int9(rs.offset())
                                                        : is_int16(rs.offset());
  if (is_one_instruction) {
    ll(rd, rs);
  } else {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    li(scratch, rs.offset());
    daddu(scratch, scratch, rs.rm());
    ll(rd, MemOperand(scratch, 0));
  }
}

void MacroAssembler::Lld(Register rd, const MemOperand& rs) {
  bool is_one_instruction = (kArchVariant == kMips64r6) ? is_int9(rs.offset())
                                                        : is_int16(rs.offset());
  if (is_one_instruction) {
    lld(rd, rs);
  } else {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    li(scratch, rs.offset());
    daddu(scratch, scratch, rs.rm());
    lld(rd, MemOperand(scratch, 0));
  }
}

void MacroAssembler::Sc(Register rd, const MemOperand& rs) {
  bool is_one_instruction = (kArchVariant == kMips64r6) ? is_int9(rs.offset())
                                                        : is_int16(rs.offset());
  if (is_one_instruction) {
    sc(rd, rs);
  } else {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    li(scratch, rs.offset());
    daddu(scratch, scratch, rs.rm());
    sc(rd, MemOperand(scratch, 0));
  }
}

void MacroAssembler::Scd(Register rd, const MemOperand& rs) {
  bool is_one_instruction = (kArchVariant == kMips64r6) ? is_int9(rs.offset())
                                                        : is_int16(rs.offset());
  if (is_one_instruction) {
    scd(rd, rs);
  } else {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    li(scratch, rs.offset());
    daddu(scratch, scratch, rs.rm());
    scd(rd, MemOperand(scratch, 0));
  }
}

void MacroAssembler::li(Register dst, Handle<HeapObject> value, LiFlags mode) {
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
      Daddu(dst, kRootRegister, Operand(reference.offset_from_root_register()));
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
  if (!is_int16(static_cast<int32_t>(value)) && (value & kUpper16MaskOf64) &&
      (value & kImm16Mask)) {
    return 2;
  } else {
    return 1;
  }
}

void MacroAssembler::LiLower32BitHelper(Register rd, Operand j) {
  if (is_int16(static_cast<int32_t>(j.immediate()))) {
    daddiu(rd, zero_reg, (j.immediate() & kImm16Mask));
  } else if (!(j.immediate() & kUpper16MaskOf64)) {
    ori(rd, zero_reg, j.immediate() & kImm16Mask);
  } else {
    lui(rd, j.immediate() >> kLuiShift & kImm16Mask);
    if (j.immediate() & kImm16Mask) {
      ori(rd, rd, j.immediate() & kImm16Mask);
    }
  }
}

static inline int InstrCountForLoadReplicatedConst32(int64_t value) {
  uint32_t x = static_cast<uint32_t>(value);
  uint32_t y = static_cast<uint32_t>(value >> 32);

  if (x == y) {
    return (is_uint16(x) || is_int16(x) || (x & kImm16Mask) == 0) ? 2 : 3;
  }

  return INT_MAX;
}

int MacroAssembler::InstrCountForLi64Bit(int64_t value) {
  if (is_int32(value)) {
    return InstrCountForLiLower32Bit(value);
  } else {
    int bit31 = value >> 31 & 0x1;
    if ((value & kUpper16MaskOf64) == 0 && is_int16(value >> 32) &&
        kArchVariant == kMips64r6) {
      return 2;
    } else if ((value & (kHigher16MaskOf64 | kUpper16MaskOf64)) == 0 &&
               kArchVariant == kMips64r6) {
      return 2;
    } else if ((value & kImm16Mask) == 0 && is_int16((value >> 32) + bit31) &&
               kArchVariant == kMips64r6) {
      return 2;
    } else if ((value & kImm16Mask) == 0 &&
               ((value >> 31) & 0x1FFFF) == ((0x20000 - bit31) & 0x1FFFF) &&
               kArchVariant == kMips64r6) {
      return 2;
    } else if (is_int16(static_cast<int32_t>(value)) &&
               is_int16((value >> 32) + bit31) && kArchVariant == kMips64r6) {
      return 2;
    } else if (is_int16(static_cast<int32_t>(value)) &&
               ((value >> 31) & 0x1FFFF) == ((0x20000 - bit31) & 0x1FFFF) &&
               kArchVariant == kMips64r6) {
      return 2;
    } else if (base::bits::IsPowerOfTwo(value + 1) ||
               value == std::numeric_limits<int64_t>::max()) {
      return 2;
    } else {
      int shift_cnt = base::bits::CountTrailingZeros64(value);
      int rep32_count = InstrCountForLoadReplicatedConst32(value);
      int64_t tmp = value >> shift_cnt;
      if (is_uint16(tmp)) {
        return 2;
      } else if (is_int16(tmp)) {
        return 2;
      } else if (rep32_count < 3) {
        return 2;
      } else if (is_int32(tmp)) {
        return 3;
      } else {
        shift_cnt = 16 + base::bits::CountTrailingZeros64(value >> 16);
        tmp = value >> shift_cnt;
        if (is_uint16(tmp)) {
          return 3;
        } else if (is_int16(tmp)) {
          return 3;
        } else if (rep32_count < 4) {
          return 3;
        } else if (kArchVariant == kMips64r6) {
          int64_t imm = value;
          int count = InstrCountForLiLower32Bit(imm);
          imm = (imm >> 32) + bit31;
          if (imm & kImm16Mask) {
            count++;
          }
          imm = (imm >> 16) + (imm >> 15 & 0x1);
          if (imm & kImm16Mask) {
            count++;
          }
          return count;
        } else {
          if (is_int48(value)) {
            int64_t k = value >> 16;
            int count = InstrCountForLiLower32Bit(k) + 1;
            if (value & kImm16Mask) {
              count++;
            }
            return count;
          } else {
            int64_t k = value >> 32;
            int count = InstrCountForLiLower32Bit(k);
            if ((value >> 16) & kImm16Mask) {
              count += 3;
              if (value & kImm16Mask) {
                count++;
              }
            } else {
              count++;
              if (value & kImm16Mask) {
                count++;
              }
            }
            return count;
          }
        }
      }
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
  BlockTrampolinePoolScope block_trampoline_pool(this);
  // Normal load of an immediate value which does not need Relocation Info.
  if (is_int32(j.immediate())) {
    LiLower32BitHelper(rd, j);
  } else {
    int bit31 = j.immediate() >> 31 & 0x1;
    if ((j.immediate() & kUpper16MaskOf64) == 0 &&
        is_int16(j.immediate() >> 32) && kArchVariant == kMips64r6) {
      // 64-bit value which consists of an unsigned 16-bit value in its
      // least significant 32-bits, and a signed 16-bit value in its
      // most significant 32-bits.
      ori(rd, zero_reg, j.immediate() & kImm16Mask);
      dahi(rd, j.immediate() >> 32 & kImm16Mask);
    } else if ((j.immediate() & (kHigher16MaskOf64 | kUpper16MaskOf64)) == 0 &&
               kArchVariant == kMips64r6) {
      // 64-bit value which consists of an unsigned 16-bit value in its
      // least significant 48-bits, and a signed 16-bit value in its
      // most significant 16-bits.
      ori(rd, zero_reg, j.immediate() & kImm16Mask);
      dati(rd, j.immediate() >> 48 & kImm16Mask);
    } else if ((j.immediate() & kImm16Mask) == 0 &&
               is_int16((j.immediate() >> 32) + bit31) &&
               kArchVariant == kMips64r6) {
      // 16 LSBs (Least Significant Bits) all set to zero.
      // 48 MSBs (Most Significant Bits) hold a signed 32-bit value.
      lui(rd, j.immediate() >> kLuiShift & kImm16Mask);
      dahi(rd, ((j.immediate() >> 32) + bit31) & kImm16Mask);
    } else if ((j.immediate() & kImm16Mask) == 0 &&
               ((j.immediate() >> 31) & 0x1FFFF) ==
                   ((0x20000 - bit31) & 0x1FFFF) &&
               kArchVariant == kMips64r6) {
      // 16 LSBs all set to zero.
      // 48 MSBs hold a signed value which can't be represented by signed
      // 32-bit number, and the middle 16 bits are all zero, or all one.
      lui(rd, j.immediate() >> kLuiShift & kImm16Mask);
      dati(rd, ((j.immediate() >> 48) + bit31) & kImm16Mask);
    } else if (is_int16(static_cast<int32_t>(j.immediate())) &&
               is_int16((j.immediate() >> 32) + bit31) &&
               kArchVariant == kMips64r6) {
      // 32 LSBs contain a signed 16-bit number.
      // 32 MSBs contain a signed 16-bit number.
      daddiu(rd, zero_reg, j.immediate() & kImm16Mask);
      dahi(rd, ((j.immediate() >> 32) + bit31) & kImm16Mask);
    } else if (is_int16(static_cast<int32_t>(j.immediate())) &&
               ((j.immediate() >> 31) & 0x1FFFF) ==
                   ((0x20000 - bit31) & 0x1FFFF) &&
               kArchVariant == kMips64r6) {
      // 48 LSBs contain an unsigned 16-bit number.
      // 16 MSBs contain a signed 16-bit number.
      daddiu(rd, zero_reg, j.immediate() & kImm16Mask);
      dati(rd, ((j.immediate() >> 48) + bit31) & kImm16Mask);
    } else if (base::bits::IsPowerOfTwo(j.immediate() + 1) ||
               j.immediate() == std::numeric_limits<int64_t>::max()) {
      // 64-bit values which have their "n" LSBs set to one, and their
      // "64-n" MSBs set to zero. "n" must meet the restrictions 0 < n < 64.
      int shift_cnt = 64 - base::bits::CountTrailingZeros64(j.immediate() + 1);
      daddiu(rd, zero_reg, -1);
      if (shift_cnt < 32) {
        dsrl(rd, rd, shift_cnt);
      } else {
        dsrl32(rd, rd, shift_cnt & 31);
      }
    } else {
      int shift_cnt = base::bits::CountTrailingZeros64(j.immediate());
      int rep32_count = InstrCountForLoadReplicatedConst32(j.immediate());
      int64_t tmp = j.immediate() >> shift_cnt;
      if (is_uint16(tmp)) {
        // Value can be computed by loading a 16-bit unsigned value, and
        // then shifting left.
        ori(rd, zero_reg, tmp & kImm16Mask);
        if (shift_cnt < 32) {
          dsll(rd, rd, shift_cnt);
        } else {
          dsll32(rd, rd, shift_cnt & 31);
        }
      } else if (is_int16(tmp)) {
        // Value can be computed by loading a 16-bit signed value, and
        // then shifting left.
        daddiu(rd, zero_reg, static_cast<int32_t>(tmp));
        if (shift_cnt < 32) {
          dsll(rd, rd, shift_cnt);
        } else {
          dsll32(rd, rd, shift_cnt & 31);
        }
      } else if (rep32_count < 3) {
        // Value being loaded has 32 LSBs equal to the 32 MSBs, and the
        // value loaded into the 32 LSBs can be loaded with a single
        // MIPS instruction.
        LiLower32BitHelper(rd, j);
        Dins(rd, rd, 32, 32);
      } else if (is_int32(tmp)) {
        // Loads with 3 instructions.
        // Value can be computed by loading a 32-bit signed value, and
        // then shifting left.
        lui(rd, tmp >> kLuiShift & kImm16Mask);
        ori(rd, rd, tmp & kImm16Mask);
        if (shift_cnt < 32) {
          dsll(rd, rd, shift_cnt);
        } else {
          dsll32(rd, rd, shift_cnt & 31);
        }
      } else {
        shift_cnt = 16 + base::bits::CountTrailingZeros64(j.immediate() >> 16);
        tmp = j.immediate() >> shift_cnt;
        if (is_uint16(tmp)) {
          // Value can be computed by loading a 16-bit unsigned value,
          // shifting left, and "or"ing in another 16-bit unsigned value.
          ori(rd, zero_reg, tmp & kImm16Mask);
          if (shift_cnt < 32) {
            dsll(rd, rd, shift_cnt);
          } else {
            dsll32(rd, rd, shift_cnt & 31);
          }
          ori(rd, rd, j.immediate() & kImm16Mask);
        } else if (is_int16(tmp)) {
          // Value can be computed by loading a 16-bit signed value,
          // shifting left, and "or"ing in a 16-bit unsigned value.
          daddiu(rd, zero_reg, static_cast<int32_t>(tmp));
          if (shift_cnt < 32) {
            dsll(rd, rd, shift_cnt);
          } else {
            dsll32(rd, rd, shift_cnt & 31);
          }
          ori(rd, rd, j.immediate() & kImm16Mask);
        } else if (rep32_count < 4) {
          // Value being loaded has 32 LSBs equal to the 32 MSBs, and the
          // value in the 32 LSBs requires 2 MIPS instructions to load.
          LiLower32BitHelper(rd, j);
          Dins(rd, rd, 32, 32);
        } else if (kArchVariant == kMips64r6) {
          // Loads with 3-4 instructions.
          // Catch-all case to get any other 64-bit values which aren't
          // handled by special cases above.
          int64_t imm = j.immediate();
          LiLower32BitHelper(rd, j);
          imm = (imm >> 32) + bit31;
          if (imm & kImm16Mask) {
            dahi(rd, imm & kImm16Mask);
          }
          imm = (imm >> 16) + (imm >> 15 & 0x1);
          if (imm & kImm16Mask) {
            dati(rd, imm & kImm16Mask);
          }
        } else {
          if (is_int48(j.immediate())) {
            Operand k = Operand(j.immediate() >> 16);
            LiLower32BitHelper(rd, k);
            dsll(rd, rd, 16);
            if (j.immediate() & kImm16Mask) {
              ori(rd, rd, j.immediate() & kImm16Mask);
            }
          } else {
            Operand k = Operand(j.immediate() >> 32);
            LiLower32BitHelper(rd, k);
            if ((j.immediate() >> 16) & kImm16Mask) {
              dsll(rd, rd, 16);
              ori(rd, rd, (j.immediate() >> 16) & kImm16Mask);
              dsll(rd, rd, 16);
              if (j.immediate() & kImm16Mask) {
                ori(rd, rd, j.immediate() & kImm16Mask);
              }
            } else {
              dsll32(rd, rd, 0);
              if (j.immediate() & kImm16Mask) {
                ori(rd, rd, j.immediate() & kImm16Mask);
              }
            }
          }
        }
      }
    }
  }
}

void MacroAssembler::li(Register rd, Operand j, LiFlags mode) {
  DCHECK(!j.is_reg());
  BlockTrampolinePoolScope block_trampoline_pool(this);
  if (!MustUseReg(j.rmode()) && mode == OPTIMIZE_SIZE) {
    int li_count = InstrCountForLi64Bit(j.immediate());
    int li_neg_count = InstrCountForLi64Bit(-j.immediate());
    int li_not_count = InstrCountForLi64Bit(~j.immediate());
    // Loading -MIN_INT64 could cause problems, but loading MIN_INT64 takes only
    // two instructions so no need to check for this.
    if (li_neg_count <= li_not_count && li_neg_count < li_count - 1) {
      DCHECK(j.immediate() != std::numeric_limits<int64_t>::min());
      li_optimized(rd, Operand(-j.immediate()), mode);
      Dsubu(rd, zero_reg, rd);
    } else if (li_neg_count > li_not_count && li_not_count < li_count - 1) {
      DCHECK(j.immediate() != std::numeric_limits<int64_t>::min());
      li_optimized(rd, Operand(~j.immediate()), mode);
      nor(rd, rd, rd);
    } else {
      li_optimized(rd, j, mode);
    }
  } else if (MustUseReg(j.rmode())) {
    int64_t immediate;
    if (j.IsHeapNumberRequest()) {
      RequestHeapNumber(j.heap_number_request());
      immediate = 0;
    } else {
      immediate = j.immediate();
    }

    RecordRelocInfo(j.rmode(), immediate);
    if (RelocInfo::IsWasmCanonicalSigId(j.rmode())) {
      // wasm_canonical_sig_id is 32-bit value.
      DCHECK(is_int32(immediate));
      lui(rd, (immediate >> 16) & kImm16Mask);
      ori(rd, rd, immediate & kImm16Mask);
      return;
    }
    lui(rd, (immediate >> 32) & kImm16Mask);
    ori(rd, rd, (immediate >> 16) & kImm16Mask);
    dsll(rd, rd, 16);
    ori(rd, rd, immediate & kImm16Mask);
  } else if (mode == ADDRESS_LOAD) {
    // We always need the same number of instructions as we may need to patch
    // this code to load another value which may need all 4 instructions.
    lui(rd, (j.immediate() >> 32) & kImm16Mask);
    ori(rd, rd, (j.immediate() >> 16) & kImm16Mask);
    dsll(rd, rd, 16);
    ori(rd, rd, j.immediate() & kImm16Mask);
  } else {  // mode == CONSTANT_SIZE - always emit the same instruction
            // sequence.
    if (kArchVariant == kMips64r6) {
      int64_t imm = j.immediate();
      lui(rd, imm >> kLuiShift & kImm16Mask);
      ori(rd, rd, (imm & kImm16Mask));
      imm = (imm >> 32) + ((imm >> 31) & 0x1);
      dahi(rd, imm & kImm16Mask & kImm16Mask);
      imm = (imm >> 16) + ((imm >> 15) & 0x1);
      dati(rd, imm & kImm16Mask & kImm16Mask);
    } else {
      lui(rd, (j.immediate() >> 48) & kImm16Mask);
      ori(rd, rd, (j.immediate() >> 32) & kImm16Mask);
      dsll(rd, rd, 16);
      ori(rd, rd, (j.immediate() >> 16) & kImm16Mask);
      dsll(rd, rd, 16);
      ori(rd, rd, j.immediate() & kImm16Mask);
    }
  }
}

void MacroAssembler::LoadIsolateField(Register dst, IsolateFieldId id) {
  li(dst, ExternalReference::Create(id));
}

void MacroAssembler::MultiPush(RegList regs) {
  int16_t num_to_push = regs.Count();
  int16_t stack_offset = num_to_push * kPointerSize;

  Dsubu(sp, sp, Operand(stack_offset));
  for (int16_t i = kNumRegisters - 1; i >= 0; i--) {
    if ((regs.bits() & (1 << i)) != 0) {
      stack_offset -= kPointerSize;
      Sd(ToRegister(i), MemOperand(sp, stack_offset));
    }
  }
}

void MacroAssembler::MultiPop(RegList regs) {
  int16_t stack_offset = 0;

  for (int16_t i = 0; i < kNumRegisters; i++) {
    if ((regs.bits() & (1 << i)) != 0) {
      Ld(ToRegister(i), MemOperand(sp, stack_offset));
      stack_offset += kPointerSize;
    }
  }
  daddiu(sp, sp, stack_offset);
}

void MacroAssembler::MultiPushFPU(DoubleRegList regs) {
  int16_t num_to_push = regs.Count();
  int16_t stack_offset = num_to_push * kDoubleSize;

  Dsubu(sp, sp, Operand(stack_offset));
  for (int16_t i = kNumRegisters - 1; i >= 0; i--) {
    if ((regs.bits() & (1 << i)) != 0) {
      stack_offset -= kDoubleSize;
      Sdc1(FPURegister::from_code(i), MemOperand(sp, stack_offset));
    }
  }
}

void MacroAssembler::MultiPopFPU(DoubleRegList regs) {
  int16_t stack_offset = 0;

  for (int16_t i = 0; i < kNumRegisters; i++) {
    if ((regs.bits() & (1 << i)) != 0) {
      Ldc1(FPURegister::from_code(i), MemOperand(sp, stack_offset));
      stack_offset += kDoubleSize;
    }
  }
  daddiu(sp, sp, stack_offset);
}

void MacroAssembler::MultiPushMSA(DoubleRegList regs) {
  int16_t num_to_push = regs.Count();
  int16_t stack_offset = num_to_push * kSimd128Size;

  Dsubu(sp, sp, Operand(stack_offset));
  for (int16_t i = kNumRegisters - 1; i >= 0; i--) {
    if ((regs.bits() & (1 << i)) != 0) {
      stack_offset -= kSimd128Size;
      st_d(MSARegister::from_code(i), MemOperand(sp, stack_offset));
    }
  }
}

void MacroAssembler::MultiPopMSA(DoubleRegList regs) {
  int16_t stack_offset = 0;

  for (int16_t i = 0; i < kNumRegisters; i++) {
    if ((regs.bits() & (1 << i)) != 0) {
      ld_d(MSARegister::from_code(i), MemOperand(sp, stack_offset));
      stack_offset += kSimd128Size;
    }
  }
  daddiu(sp, sp, stack_offset);
}

void MacroAssembler::Ext(Register rt, Register rs, uint16_t pos,
                         uint16_t size) {
  DCHECK_LT(pos, 32);
  DCHECK_LT(pos + size, 33);
  ext_(rt, rs, pos, size);
}

void MacroAssembler::Dext(Register rt, Register rs, uint16_t pos,
                          uint16_t size) {
  DCHECK(pos < 64 && 0 < size && size <= 64 && 0 < pos + size &&
         pos + size <= 64);
  if (size > 32) {
    dextm_(rt, rs, pos, size);
  } else if (pos >= 32) {
    dextu_(rt, rs, pos, size);
  } else {
    dext_(rt, rs, pos, size);
  }
}

void MacroAssembler::Ins(Register rt, Register rs, uint16_t pos,
                         uint16_t size) {
  DCHECK_LT(pos, 32);
  DCHECK_LE(pos + size, 32);
  DCHECK_NE(size, 0);
  ins_(rt, rs, pos, size);
}

void MacroAssembler::Dins(Register rt, Register rs, uint16_t pos,
                          uint16_t size) {
  DCHECK(pos < 64 && 0 < size && size <= 64 && 0 < pos + size &&
         pos + size <= 64);
  if (pos + size <= 32) {
    dins_(rt, rs, pos, size);
  } else if (pos < 32) {
    dinsm_(rt, rs, pos, size);
  } else {
    dinsu_(rt, rs, pos, size);
  }
}

void MacroAssembler::ExtractBits(Register dest, Register source, Register pos,
                                 int size, bool sign_extend) {
  dsrav(dest, source, pos);
  Dext(dest, dest, 0, size);
  if (sign_extend) {
    switch (size) {
      case 8:
        seb(dest, dest);
        break;
      case 16:
        seh(dest, dest);
        break;
      case 32:
        // sign-extend word
        sll(dest, dest, 0);
        break;
      default:
        UNREACHABLE();
    }
  }
}

void MacroAssembler::InsertBits(Register dest, Register source, Register pos,
                                int size) {
  Dror(dest, dest, pos);
  Dins(dest, source, 0, size);
  {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    Dsubu(scratch, zero_reg, pos);
    Dror(dest, dest, scratch);
  }
}

void MacroAssembler::Neg_s(FPURegister fd, FPURegister fs) {
  if (kArchVariant == kMips64r6) {
    // r6 neg_s changes the sign for NaN-like operands as well.
    neg_s(fd, fs);
  } else {
    DCHECK_EQ(kArchVariant, kMips64r2);
    BlockTrampolinePoolScope block_trampoline_pool(this);
    Label is_nan, done;
    Register scratch1 = t8;
    Register scratch2 = t9;
    CompareIsNanF32(fs, fs);
    BranchTrueShortF(&is_nan);
    Branch(USE_DELAY_SLOT, &done);
    // For NaN input, neg_s will return the same NaN value,
    // while the sign has to be changed separately.
    neg_s(fd, fs);  // In delay slot.
    bind(&is_nan);
    mfc1(scratch1, fs);
    li(scratch2, kBinary32SignMask);
    Xor(scratch1, scratch1, scratch2);
    mtc1(scratch1, fd);
    bind(&done);
  }
}

void MacroAssembler::Neg_d(FPURegister fd, FPURegister fs) {
  if (kArchVariant == kMips64r6) {
    // r6 neg_d changes the sign for NaN-like operands as well.
    neg_d(fd, fs);
  } else {
    DCHECK_EQ(kArchVariant, kMips64r2);
    BlockTrampolinePoolScope block_trampoline_pool(this);
    Label is_nan, done;
    Register scratch1 = t8;
    Register scratch2 = t9;
    CompareIsNanF64(fs, fs);
    BranchTrueShortF(&is_nan);
    Branch(USE_DELAY_SLOT, &done);
    // For NaN input, neg_d will return the same NaN value,
    // while the sign has to be changed separately.
    neg_d(fd, fs);  // In delay slot.
    bind(&is_nan);
    dmfc1(scratch1, fs);
    li(scratch2, base::Double::kSignMask);
    Xor(scratch1, scratch1, scratch2);
    dmtc1(scratch1, fd);
    bind(&done);
  }
}

void MacroAssembler::Cvt_d_uw(FPURegister fd, FPURegister fs) {
  // Move the data from fs to t8.
  BlockTrampolinePoolScope
```