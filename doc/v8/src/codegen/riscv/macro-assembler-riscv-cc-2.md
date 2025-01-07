Response:
The user wants a summary of the provided C++ code snippet from `v8/src/codegen/riscv/macro-assembler-riscv.cc`.

Here's a breakdown of the code's functionality:

1. **Memory Access Instructions:** The code defines helper functions for loading and storing data of various sizes (bytes, words, double words) from memory. It handles both aligned and unaligned memory access.

2. **Unaligned Access Helpers:**  The `UnalignedLoadHelper` and `UnalignedStoreHelper` functions are central to handling memory accesses that don't fall on natural alignment boundaries. These involve potentially loading/storing data in multiple steps and using temporary registers.

3. **Floating-Point Load/Store:**  Specific helpers (`UnalignedFLoadHelper`, `UnalignedFStoreHelper`, `UnalignedDoubleHelper`, `UnalignedDStoreHelper`) manage unaligned loads and stores for floating-point values (single and double precision).

4. **Aligned Access Helpers:**  `AlignedLoadHelper` and `AlignedStoreHelper` simplify the generation of aligned memory access instructions, potentially adjusting base registers and offsets.

5. **Load Immediate (li):**  The code includes functions to load immediate values into registers, optimizing for size and handling different types of immediate values (handles, external references).

6. **Stack Operations (MultiPush/MultiPop):**  Functions `MultiPush` and `MultiPop` are provided to efficiently push and pop multiple registers onto and from the stack. There are also versions for floating-point registers.

7. **Atomic Operations (Ll/Sc):**  Functions `Ll` (Load-linked) and `Sc` (Store-conditional) provide support for atomic memory operations, ensuring exclusive access in multi-threaded environments.

8. **Arithmetic Operations (Pair Operations - RISCV32):** For the RISCV32 architecture, there are functions to perform arithmetic and logical operations on 64-bit values represented as pairs of 32-bit registers (`AddPair`, `SubPair`, `AndPair`, `OrPair`, `XorPair`, `MulPair`, `ShlPair`).

Considering this is part 3 of 9, and focusing on the provided code, I can summarize its function as providing a set of higher-level abstractions for common RISC-V assembly operations, especially related to memory access and register manipulation.这是 `v8/src/codegen/riscv/macro-assembler-riscv.cc` 源代码的第三部分，主要功能是提供了一系列用于在 RISC-V 架构上进行内存加载、存储和一些特定的寄存器操作的宏指令。

**主要功能归纳:**

1. **非对齐内存访问辅助函数:**  定义了用于处理非对齐内存加载 (`UnalignedLoadHelper`) 和存储 (`UnalignedStoreHelper`) 的模板函数。这些函数可以处理不同大小（NBYTES）的数据，并区分有符号和无符号加载。对于浮点数也有专门的非对齐加载和存储辅助函数 (`UnalignedFLoadHelper`, `UnalignedFStoreHelper`, `UnalignedDoubleHelper`, `UnalignedDStoreHelper`)。

2. **对齐内存访问辅助函数:**  定义了用于处理对齐内存加载 (`AlignedLoadHelper`) 和存储 (`AlignedStoreHelper`) 的模板函数，这些函数会检查是否需要调整基址和偏移量。

3. **Load Immediate 指令 (`li`) 的多种实现:**  提供了多种 `li` 指令的实现，用于将立即数加载到寄存器中，包括加载 Handle、外部引用以及优化大小的加载方式。

4. **多寄存器压栈和出栈 (`MultiPush`, `MultiPop`)**: 提供了将多个通用寄存器和浮点寄存器压入和弹出堆栈的功能。

5. **原子加载和存储指令 (`Ll`, `Sc`)**: 提供了原子加载 (`Ll`) 和存储 (`Sc`) 的宏指令，用于实现并发控制。

6. **64 位整数运算辅助函数 (RISCV32):**  在 RISCV32 架构下，提供了一系列辅助函数，用于进行 64 位整数的加法 (`AddPair`)、减法 (`SubPair`)、按位与 (`AndPair`)、按位或 (`OrPair`)、按位异或 (`XorPair`)、乘法 (`MulPair`) 和左移 (`ShlPair`) 操作，这些操作使用两个 32 位寄存器来表示一个 64 位的值。

**关于是否为 Torque 源代码:**

`v8/src/codegen/riscv/macro-assembler-riscv.cc` 以 `.cc` 结尾，表明它是一个 C++ 源代码文件，而不是以 `.tq` 结尾的 Torque 源代码文件。Torque 是一种用于 V8 内部的领域特定语言，用于定义运行时函数的低级实现。

**与 JavaScript 功能的关系及示例:**

这些宏指令最终会被 V8 的 JavaScript 引擎在执行 JavaScript 代码时使用。例如，当 JavaScript 代码访问对象的属性或数组元素时，可能需要进行内存加载；当给变量赋值时，可能需要进行内存存储。

```javascript
// JavaScript 示例

let obj = { a: 10, b: 20 };
let x = obj.a; // 读取 obj 的属性 'a'，这可能涉及到内存加载操作
obj.b = 30;    // 修改 obj 的属性 'b'，这可能涉及到内存存储操作

function add(a, b) {
  return a + b;
}
let result = add(5, 7); // 函数调用和返回可能涉及到寄存器的压栈和出栈
```

在底层的汇编代码层面，`MacroAssembler` 提供的这些宏指令会被用来生成实际的 RISC-V 汇编指令来完成这些操作。例如，读取 `obj.a` 可能最终会生成一个 `lw` (load word) 指令，而修改 `obj.b` 可能会生成一个 `sw` (store word) 指令。

**代码逻辑推理与假设输入输出:**

以 `LoadNBytes` 函数为例：

```c++
template <int NBYTES, bool LOAD_SIGNED>
void MacroAssembler::LoadNBytes(Register rd, const MemOperand& rs,
                                Register scratch) {
  // ... (函数体)
}
```

**假设输入:**

* `NBYTES = 4` (加载 4 个字节，即一个 word)
* `LOAD_SIGNED = true` (有符号加载)
* `rd = a0` (目标寄存器)
* `rs` 表示内存地址，例如 `MemOperand(s0, 8)` (基址寄存器 s0，偏移量 8)
* `scratch = t0` (临时寄存器)

**预期输出 (抽象的 RISC-V 指令序列):**

```assembly
lb a0, 11(s0)  // 加载最高有效字节 (带符号) 到 a0
slli a0, a0, 24 // 左移 24 位
lbu t0, 10(s0) // 加载下一个字节 (无符号) 到 t0
slli t0, t0, 16 // 左移 16 位
or a0, a0, t0  // 合并到 a0
lbu t0, 9(s0)  // 加载下一个字节 (无符号) 到 t0
slli t0, t0, 8  // 左移 8 位
or a0, a0, t0  // 合并到 a0
lbu t0, 8(s0)  // 加载最低有效字节 (无符号) 到 t0
or a0, a0, t0  // 合并到 a0
```

**用户常见的编程错误举例:**

在使用这些宏指令时，用户（通常是 V8 引擎的开发者）可能会犯以下错误：

1. **寄存器冲突:**  例如，在 `LoadNBytes` 中，如果 `rd` 和 `scratch` 使用了相同的寄存器，会导致数据被覆盖。宏指令中使用了 `DCHECK` 来避免这种情况。
2. **非对齐访问未处理:**  如果直接使用对齐的加载/存储指令访问非对齐的地址，会导致程序崩溃或数据错误。`UnalignedLoadHelper` 和 `UnalignedStoreHelper` 就是为了解决这个问题。但如果开发者没有正确使用这些辅助函数，就会出错。
3. **立即数超出范围:** 在使用 `li` 指令加载立即数时，如果立即数超出了 RISC-V 指令的表示范围，需要使用多条指令来加载。错误地假设立即数在范围内可能导致加载错误的值。
4. **堆栈操作不匹配:** `MultiPush` 和 `MultiPop` 必须成对使用，且压栈和出栈的寄存器列表要匹配。不匹配会导致堆栈损坏。

**总结 (针对第 3 部分):**

这部分代码主要集中在提供用于高效且安全地进行内存访问（包括对齐和非对齐访问）以及一些基本的寄存器操作的宏指令。它为 V8 引擎的 RISC-V 代码生成器提供了底层的 building blocks，使得生成正确的汇编代码来执行 JavaScript 成为可能。 特别是非对齐内存访问的处理和 `li` 指令的多种实现方式是这部分代码的核心功能。

Prompt: 
```
这是目录为v8/src/codegen/riscv/macro-assembler-riscv.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/riscv/macro-assembler-riscv.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共9部分，请归纳一下它的功能

"""
   slli(x1, x1, 8);   // x1 <- 0xFF00FF00
    and_(rd, x0, x1);  // x0 & 0xFF00FF00
    srli(rd, rd, 8);
    or_(rd, rd, x2);  // (((x0 & x1) << 8)  | ((x0 & (x1 << 8)) >> 8))
  }
}
#endif

template <int NBYTES, bool LOAD_SIGNED>
void MacroAssembler::LoadNBytes(Register rd, const MemOperand& rs,
                                Register scratch) {
  DCHECK(rd != rs.rm() && rd != scratch);
  DCHECK_LE(NBYTES, 8);

  // load the most significant byte
  if (LOAD_SIGNED) {
    lb(rd, rs.rm(), rs.offset() + (NBYTES - 1));
  } else {
    lbu(rd, rs.rm(), rs.offset() + (NBYTES - 1));
  }

  // load remaining (nbytes-1) bytes from higher to lower
  slli(rd, rd, 8 * (NBYTES - 1));
  for (int i = (NBYTES - 2); i >= 0; i--) {
    lbu(scratch, rs.rm(), rs.offset() + i);
    if (i) slli(scratch, scratch, i * 8);
    or_(rd, rd, scratch);
  }
}

template <int NBYTES, bool LOAD_SIGNED>
void MacroAssembler::LoadNBytesOverwritingBaseReg(const MemOperand& rs,
                                                  Register scratch0,
                                                  Register scratch1) {
  // This function loads nbytes from memory specified by rs and into rs.rm()
  DCHECK(rs.rm() != scratch0 && rs.rm() != scratch1 && scratch0 != scratch1);
  DCHECK_LE(NBYTES, 8);

  // load the most significant byte
  if (LOAD_SIGNED) {
    lb(scratch0, rs.rm(), rs.offset() + (NBYTES - 1));
  } else {
    lbu(scratch0, rs.rm(), rs.offset() + (NBYTES - 1));
  }

  // load remaining (nbytes-1) bytes from higher to lower
  slli(scratch0, scratch0, 8 * (NBYTES - 1));
  for (int i = (NBYTES - 2); i >= 0; i--) {
    lbu(scratch1, rs.rm(), rs.offset() + i);
    if (i) {
      slli(scratch1, scratch1, i * 8);
      or_(scratch0, scratch0, scratch1);
    } else {
      // write to rs.rm() when processing the last byte
      or_(rs.rm(), scratch0, scratch1);
    }
  }
}

template <int NBYTES, bool IS_SIGNED>
void MacroAssembler::UnalignedLoadHelper(Register rd, const MemOperand& rs) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  UseScratchRegisterScope temps(this);

  if (NeedAdjustBaseAndOffset(rs, OffsetAccessType::TWO_ACCESSES, NBYTES - 1)) {
    // Adjust offset for two accesses and check if offset + 3 fits into int12.
    MemOperand source = rs;
    Register scratch_base = temps.Acquire();
    DCHECK(scratch_base != rs.rm());
    AdjustBaseAndOffset(&source, scratch_base, OffsetAccessType::TWO_ACCESSES,
                        NBYTES - 1);

    // Since source.rm() is scratch_base, assume rd != source.rm()
    DCHECK(rd != source.rm());
    Register scratch_other = temps.Acquire();
    LoadNBytes<NBYTES, IS_SIGNED>(rd, source, scratch_other);
  } else {
    // no need to adjust base-and-offset
    if (rd != rs.rm()) {
      Register scratch = temps.Acquire();
      LoadNBytes<NBYTES, IS_SIGNED>(rd, rs, scratch);
    } else {  // rd == rs.rm()
      Register scratch = temps.Acquire();
      Register scratch2 = temps.Acquire();
      LoadNBytesOverwritingBaseReg<NBYTES, IS_SIGNED>(rs, scratch, scratch2);
    }
  }
}

#if V8_TARGET_ARCH_RISCV64
template <int NBYTES>
void MacroAssembler::UnalignedFLoadHelper(FPURegister frd, const MemOperand& rs,
                                          Register scratch_base) {
  DCHECK(NBYTES == 4 || NBYTES == 8);
  DCHECK_NE(scratch_base, rs.rm());
  BlockTrampolinePoolScope block_trampoline_pool(this);
  MemOperand source = rs;
  if (NeedAdjustBaseAndOffset(rs, OffsetAccessType::TWO_ACCESSES, NBYTES - 1)) {
    // Adjust offset for two accesses and check if offset + 3 fits into int12.
    DCHECK(scratch_base != rs.rm());
    AdjustBaseAndOffset(&source, scratch_base, OffsetAccessType::TWO_ACCESSES,
                        NBYTES - 1);
  }
  UseScratchRegisterScope temps(this);
  Register scratch_other = temps.Acquire();
  Register scratch = temps.Acquire();
  DCHECK(scratch != rs.rm() && scratch_other != scratch &&
         scratch_other != rs.rm());
  LoadNBytes<NBYTES, true>(scratch, source, scratch_other);
  if (NBYTES == 4)
    fmv_w_x(frd, scratch);
  else
    fmv_d_x(frd, scratch);
}
#elif V8_TARGET_ARCH_RISCV32
template <int NBYTES>
void MacroAssembler::UnalignedFLoadHelper(FPURegister frd, const MemOperand& rs,
                                          Register scratch_base) {
  DCHECK_EQ(NBYTES, 4);
  DCHECK_NE(scratch_base, rs.rm());
  BlockTrampolinePoolScope block_trampoline_pool(this);
  MemOperand source = rs;
  if (NeedAdjustBaseAndOffset(rs, OffsetAccessType::TWO_ACCESSES, NBYTES - 1)) {
    // Adjust offset for two accesses and check if offset + 3 fits into int12.
    DCHECK(scratch_base != rs.rm());
    AdjustBaseAndOffset(&source, scratch_base, OffsetAccessType::TWO_ACCESSES,
                        NBYTES - 1);
  }
  UseScratchRegisterScope temps(this);
  Register scratch_other = temps.Acquire();
  Register scratch = temps.Acquire();
  DCHECK(scratch != rs.rm() && scratch_other != scratch &&
         scratch_other != rs.rm());
  LoadNBytes<NBYTES, true>(scratch, source, scratch_other);
  fmv_w_x(frd, scratch);
}

void MacroAssembler::UnalignedDoubleHelper(FPURegister frd,
                                           const MemOperand& rs,
                                           Register scratch_base) {
  DCHECK_NE(scratch_base, rs.rm());
  BlockTrampolinePoolScope block_trampoline_pool(this);
  MemOperand source = rs;
  if (NeedAdjustBaseAndOffset(rs, OffsetAccessType::TWO_ACCESSES, 8 - 1)) {
    // Adjust offset for two accesses and check if offset + 3 fits into int12.
    DCHECK(scratch_base != rs.rm());
    AdjustBaseAndOffset(&source, scratch_base, OffsetAccessType::TWO_ACCESSES,
                        8 - 1);
  }
  UseScratchRegisterScope temps(this);
  Register scratch_other = temps.Acquire();
  Register scratch = temps.Acquire();
  DCHECK(scratch != rs.rm() && scratch_other != scratch &&
         scratch_other != rs.rm());
  LoadNBytes<4, true>(scratch, source, scratch_other);
  SubWord(sp, sp, 8);
  Sw(scratch, MemOperand(sp, 0));
  source.set_offset(source.offset() + 4);
  LoadNBytes<4, true>(scratch, source, scratch_other);
  Sw(scratch, MemOperand(sp, 4));
  LoadDouble(frd, MemOperand(sp, 0));
  AddWord(sp, sp, 8);
}
#endif

template <int NBYTES>
void MacroAssembler::UnalignedStoreHelper(Register rd, const MemOperand& rs,
                                          Register scratch_other) {
  DCHECK(scratch_other != rs.rm());
  DCHECK_LE(NBYTES, 8);
  MemOperand source = rs;
  UseScratchRegisterScope temps(this);
  Register scratch_base = temps.Acquire();
  // Adjust offset for two accesses and check if offset + 3 fits into int12.
  if (NeedAdjustBaseAndOffset(rs, OffsetAccessType::TWO_ACCESSES, NBYTES - 1)) {
    DCHECK(scratch_base != rd && scratch_base != rs.rm());
    AdjustBaseAndOffset(&source, scratch_base, OffsetAccessType::TWO_ACCESSES,
                        NBYTES - 1);
  }

  BlockTrampolinePoolScope block_trampoline_pool(this);
  if (scratch_other == no_reg) {
    if (temps.CanAcquire()) {
      scratch_other = temps.Acquire();
    } else {
      push(t2);
      scratch_other = t2;
    }
  }

  DCHECK(scratch_other != rd && scratch_other != rs.rm() &&
         scratch_other != source.rm());

  sb(rd, source.rm(), source.offset());
  for (size_t i = 1; i <= (NBYTES - 1); i++) {
    srli(scratch_other, rd, i * 8);
    sb(scratch_other, source.rm(), source.offset() + i);
  }
  if (scratch_other == t2) {
    pop(t2);
  }
}

#if V8_TARGET_ARCH_RISCV64
template <int NBYTES>
void MacroAssembler::UnalignedFStoreHelper(FPURegister frd,
                                           const MemOperand& rs,
                                           Register scratch) {
  DCHECK(NBYTES == 8 || NBYTES == 4);
  DCHECK_NE(scratch, rs.rm());
  if (NBYTES == 4) {
    fmv_x_w(scratch, frd);
  } else {
    fmv_x_d(scratch, frd);
  }
  UnalignedStoreHelper<NBYTES>(scratch, rs);
}
#elif V8_TARGET_ARCH_RISCV32
template <int NBYTES>
void MacroAssembler::UnalignedFStoreHelper(FPURegister frd,
                                           const MemOperand& rs,
                                           Register scratch) {
  DCHECK_EQ(NBYTES, 4);
  DCHECK_NE(scratch, rs.rm());
  fmv_x_w(scratch, frd);
  UnalignedStoreHelper<NBYTES>(scratch, rs);
}
void MacroAssembler::UnalignedDStoreHelper(FPURegister frd,
                                           const MemOperand& rs,
                                           Register scratch) {
  DCHECK_NE(scratch, rs.rm());
  Sub32(sp, sp, 8);
  StoreDouble(frd, MemOperand(sp, 0));
  Lw(scratch, MemOperand(sp, 0));
  UnalignedStoreHelper<4>(scratch, rs);
  Lw(scratch, MemOperand(sp, 4));
  MemOperand source = rs;
  source.set_offset(source.offset() + 4);
  UnalignedStoreHelper<4>(scratch, source);
  Add32(sp, sp, 8);
}
#endif

template <typename Reg_T, typename Func>
void MacroAssembler::AlignedLoadHelper(Reg_T target, const MemOperand& rs,
                                       Func generator) {
  MemOperand source = rs;
  UseScratchRegisterScope temps(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  if (NeedAdjustBaseAndOffset(source)) {
    Register scratch = temps.Acquire();
    DCHECK(scratch != rs.rm());
    AdjustBaseAndOffset(&source, scratch);
  }
  generator(target, source);
}

template <typename Reg_T, typename Func>
void MacroAssembler::AlignedStoreHelper(Reg_T value, const MemOperand& rs,
                                        Func generator) {
  MemOperand source = rs;
  UseScratchRegisterScope temps(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  if (NeedAdjustBaseAndOffset(source)) {
    Register scratch = temps.Acquire();
    // make sure scratch does not overwrite value
    if (std::is_same<Reg_T, Register>::value)
      DCHECK(scratch.code() != value.code());
    DCHECK(scratch != rs.rm());
    AdjustBaseAndOffset(&source, scratch);
  }
  generator(value, source);
}

void MacroAssembler::Ulw(Register rd, const MemOperand& rs) {
  UnalignedLoadHelper<4, true>(rd, rs);
}

#if V8_TARGET_ARCH_RISCV64
void MacroAssembler::Ulwu(Register rd, const MemOperand& rs) {
  UnalignedLoadHelper<4, false>(rd, rs);
}
#endif
void MacroAssembler::Usw(Register rd, const MemOperand& rs) {
  UnalignedStoreHelper<4>(rd, rs);
}

void MacroAssembler::Ulh(Register rd, const MemOperand& rs) {
  UnalignedLoadHelper<2, true>(rd, rs);
}

void MacroAssembler::Ulhu(Register rd, const MemOperand& rs) {
  UnalignedLoadHelper<2, false>(rd, rs);
}

void MacroAssembler::Ush(Register rd, const MemOperand& rs) {
  UnalignedStoreHelper<2>(rd, rs);
}

void MacroAssembler::Uld(Register rd, const MemOperand& rs) {
  UnalignedLoadHelper<8, true>(rd, rs);
}
#if V8_TARGET_ARCH_RISCV64
// Load consequent 32-bit word pair in 64-bit reg. and put first word in low
// bits,
// second word in high bits.
void MacroAssembler::LoadWordPair(Register rd, const MemOperand& rs) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  Lwu(rd, rs);
  Lw(scratch, MemOperand(rs.rm(), rs.offset() + kSystemPointerSize / 2));
  slli(scratch, scratch, 32);
  AddWord(rd, rd, scratch);
}

// Do 64-bit store as two consequent 32-bit stores to unaligned address.
void MacroAssembler::StoreWordPair(Register rd, const MemOperand& rs) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  Sw(rd, rs);
  srai(scratch, rd, 32);
  Sw(scratch, MemOperand(rs.rm(), rs.offset() + kSystemPointerSize / 2));
}
#endif

void MacroAssembler::Usd(Register rd, const MemOperand& rs) {
  UnalignedStoreHelper<8>(rd, rs);
}

void MacroAssembler::ULoadFloat(FPURegister fd, const MemOperand& rs,
                                Register scratch) {
  DCHECK_NE(scratch, rs.rm());
  UnalignedFLoadHelper<4>(fd, rs, scratch);
}

void MacroAssembler::UStoreFloat(FPURegister fd, const MemOperand& rs,
                                 Register scratch) {
  DCHECK_NE(scratch, rs.rm());
  UnalignedFStoreHelper<4>(fd, rs, scratch);
}

void MacroAssembler::ULoadDouble(FPURegister fd, const MemOperand& rs,
                                 Register scratch) {
  DCHECK_NE(scratch, rs.rm());
#if V8_TARGET_ARCH_RISCV64
  UnalignedFLoadHelper<8>(fd, rs, scratch);
#elif V8_TARGET_ARCH_RISCV32
  UnalignedDoubleHelper(fd, rs, scratch);
#endif
}

void MacroAssembler::UStoreDouble(FPURegister fd, const MemOperand& rs,
                                  Register scratch) {
  DCHECK_NE(scratch, rs.rm());
#if V8_TARGET_ARCH_RISCV64
  UnalignedFStoreHelper<8>(fd, rs, scratch);
#elif V8_TARGET_ARCH_RISCV32
  UnalignedDStoreHelper(fd, rs, scratch);
#endif
}

void MacroAssembler::Lb(Register rd, const MemOperand& rs, Trapper&& trapper) {
  auto fn = [&](Register target, const MemOperand& source) {
    trapper(pc_offset());
    lb(target, source.rm(), source.offset());
  };
  AlignedLoadHelper(rd, rs, fn);
}

void MacroAssembler::Lbu(Register rd, const MemOperand& rs, Trapper&& trapper) {
  auto fn = [&](Register target, const MemOperand& source) {
    trapper(pc_offset());
    lbu(target, source.rm(), source.offset());
  };
  AlignedLoadHelper(rd, rs, fn);
}

void MacroAssembler::Sb(Register rd, const MemOperand& rs, Trapper&& trapper) {
  auto fn = [&](Register value, const MemOperand& source) {
    trapper(pc_offset());
    sb(value, source.rm(), source.offset());
  };
  AlignedStoreHelper(rd, rs, fn);
}

void MacroAssembler::Lh(Register rd, const MemOperand& rs, Trapper&& trapper) {
  auto fn = [&](Register target, const MemOperand& source) {
    trapper(pc_offset());
    lh(target, source.rm(), source.offset());
  };
  AlignedLoadHelper(rd, rs, fn);
}

void MacroAssembler::Lhu(Register rd, const MemOperand& rs, Trapper&& trapper) {
  auto fn = [&](Register target, const MemOperand& source) {
    trapper(pc_offset());
    lhu(target, source.rm(), source.offset());
  };
  AlignedLoadHelper(rd, rs, fn);
}

void MacroAssembler::Sh(Register rd, const MemOperand& rs, Trapper&& trapper) {
  auto fn = [&](Register value, const MemOperand& source) {
    trapper(pc_offset());
    sh(value, source.rm(), source.offset());
  };
  AlignedStoreHelper(rd, rs, fn);
}

void MacroAssembler::Lw(Register rd, const MemOperand& rs, Trapper&& trapper) {
  auto fn = [&](Register target, const MemOperand& source) {
    trapper(pc_offset());
    if (v8_flags.riscv_c_extension && ((target.code() & 0b11000) == 0b01000) &&
        ((source.rm().code() & 0b11000) == 0b01000) &&
        is_uint7(source.offset()) && ((source.offset() & 0x3) == 0)) {
      c_lw(target, source.rm(), source.offset());
    } else if (v8_flags.riscv_c_extension && (target != zero_reg) &&
               is_uint8(source.offset()) && (source.rm() == sp) &&
               ((source.offset() & 0x3) == 0)) {
      c_lwsp(target, source.offset());
    } else {
      lw(target, source.rm(), source.offset());
    }
  };
  AlignedLoadHelper(rd, rs, fn);
}

#if V8_TARGET_ARCH_RISCV64
void MacroAssembler::Lwu(Register rd, const MemOperand& rs, Trapper&& trapper) {
  auto fn = [&](Register target, const MemOperand& source) {
    trapper(pc_offset());
    lwu(target, source.rm(), source.offset());
  };
  AlignedLoadHelper(rd, rs, fn);
}
#endif

void MacroAssembler::Sw(Register rd, const MemOperand& rs, Trapper&& trapper) {
  auto fn = [&](Register value, const MemOperand& source) {
    trapper(pc_offset());
    if (v8_flags.riscv_c_extension && ((value.code() & 0b11000) == 0b01000) &&
        ((source.rm().code() & 0b11000) == 0b01000) &&
        is_uint7(source.offset()) && ((source.offset() & 0x3) == 0)) {
      c_sw(value, source.rm(), source.offset());
    } else if (v8_flags.riscv_c_extension && (source.rm() == sp) &&
               is_uint8(source.offset()) && (((source.offset() & 0x3) == 0))) {
      c_swsp(value, source.offset());
    } else {
      sw(value, source.rm(), source.offset());
    }
  };
  AlignedStoreHelper(rd, rs, fn);
}

#if V8_TARGET_ARCH_RISCV64
void MacroAssembler::Ld(Register rd, const MemOperand& rs, Trapper&& trapper) {
  auto fn = [&](Register target, const MemOperand& source) {
    trapper(pc_offset());
    if (v8_flags.riscv_c_extension && ((target.code() & 0b11000) == 0b01000) &&
        ((source.rm().code() & 0b11000) == 0b01000) &&
        is_uint8(source.offset()) && ((source.offset() & 0x7) == 0)) {
      c_ld(target, source.rm(), source.offset());
    } else if (v8_flags.riscv_c_extension && (target != zero_reg) &&
               is_uint9(source.offset()) && (source.rm() == sp) &&
               ((source.offset() & 0x7) == 0)) {
      c_ldsp(target, source.offset());
    } else {
      ld(target, source.rm(), source.offset());
    }
  };
  AlignedLoadHelper(rd, rs, fn);
}

void MacroAssembler::Sd(Register rd, const MemOperand& rs, Trapper&& trapper) {
  auto fn = [&](Register value, const MemOperand& source) {
    trapper(pc_offset());
    if (v8_flags.riscv_c_extension && ((value.code() & 0b11000) == 0b01000) &&
        ((source.rm().code() & 0b11000) == 0b01000) &&
        is_uint8(source.offset()) && ((source.offset() & 0x7) == 0)) {
      c_sd(value, source.rm(), source.offset());
    } else if (v8_flags.riscv_c_extension && (source.rm() == sp) &&
               is_uint9(source.offset()) && ((source.offset() & 0x7) == 0)) {
      c_sdsp(value, source.offset());
    } else {
      sd(value, source.rm(), source.offset());
    }
  };
  AlignedStoreHelper(rd, rs, fn);
}
#endif

void MacroAssembler::LoadFloat(FPURegister fd, const MemOperand& src,
                               Trapper&& trapper) {
  auto fn = [&](FPURegister target, const MemOperand& source) {
    trapper(pc_offset());
    flw(target, source.rm(), source.offset());
  };
  AlignedLoadHelper(fd, src, fn);
}

void MacroAssembler::StoreFloat(FPURegister fs, const MemOperand& src,
                                Trapper&& trapper) {
  auto fn = [&](FPURegister value, const MemOperand& source) {
    trapper(pc_offset());
    fsw(value, source.rm(), source.offset());
  };
  AlignedStoreHelper(fs, src, fn);
}

void MacroAssembler::LoadDouble(FPURegister fd, const MemOperand& src,
                                Trapper&& trapper) {
  auto fn = [&](FPURegister target, const MemOperand& source) {
    trapper(pc_offset());
    if (v8_flags.riscv_c_extension && ((target.code() & 0b11000) == 0b01000) &&
        ((source.rm().code() & 0b11000) == 0b01000) &&
        is_uint8(source.offset()) && ((source.offset() & 0x7) == 0)) {
      c_fld(target, source.rm(), source.offset());
    } else if (v8_flags.riscv_c_extension && (source.rm() == sp) &&
               is_uint9(source.offset()) && ((source.offset() & 0x7) == 0)) {
      c_fldsp(target, source.offset());
    } else {
      fld(target, source.rm(), source.offset());
    }
  };
  AlignedLoadHelper(fd, src, fn);
}

void MacroAssembler::StoreDouble(FPURegister fs, const MemOperand& src,
                                 Trapper&& trapper) {
  auto fn = [&](FPURegister value, const MemOperand& source) {
    trapper(pc_offset());
    if (v8_flags.riscv_c_extension && ((value.code() & 0b11000) == 0b01000) &&
        ((source.rm().code() & 0b11000) == 0b01000) &&
        is_uint8(source.offset()) && ((source.offset() & 0x7) == 0)) {
      c_fsd(value, source.rm(), source.offset());
    } else if (v8_flags.riscv_c_extension && (source.rm() == sp) &&
               is_uint9(source.offset()) && ((source.offset() & 0x7) == 0)) {
      c_fsdsp(value, source.offset());
    } else {
      fsd(value, source.rm(), source.offset());
    }
  };
  AlignedStoreHelper(fs, src, fn);
}

void MacroAssembler::Ll(Register rd, const MemOperand& rs, Trapper&& trapper) {
  bool is_one_instruction = rs.offset() == 0;
  if (is_one_instruction) {
    trapper(pc_offset());
    lr_w(false, false, rd, rs.rm());
  } else {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    AddWord(scratch, rs.rm(), rs.offset());
    trapper(pc_offset());
    lr_w(false, false, rd, scratch);
  }
}

#if V8_TARGET_ARCH_RISCV64
void MacroAssembler::Lld(Register rd, const MemOperand& rs, Trapper&& trapper) {
  bool is_one_instruction = rs.offset() == 0;
  if (is_one_instruction) {
    trapper(pc_offset());
    lr_d(false, false, rd, rs.rm());
  } else {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    AddWord(scratch, rs.rm(), rs.offset());
    trapper(pc_offset());
    lr_d(false, false, rd, scratch);
  }
}
#endif

void MacroAssembler::Sc(Register rd, const MemOperand& rs, Trapper&& trapper) {
  bool is_one_instruction = rs.offset() == 0;
  if (is_one_instruction) {
    trapper(pc_offset());
    sc_w(false, false, rd, rs.rm(), rd);
  } else {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    AddWord(scratch, rs.rm(), rs.offset());
    trapper(pc_offset());
    sc_w(false, false, rd, scratch, rd);
  }
}

#if V8_TARGET_ARCH_RISCV64
void MacroAssembler::Scd(Register rd, const MemOperand& rs, Trapper&& trapper) {
  bool is_one_instruction = rs.offset() == 0;
  if (is_one_instruction) {
    trapper(pc_offset());
    sc_d(false, false, rd, rs.rm(), rd);
  } else {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    AddWord(scratch, rs.rm(), rs.offset());
    trapper(pc_offset());
    sc_d(false, false, rd, scratch, rd);
  }
}
#endif

void MacroAssembler::li(Register dst, Handle<HeapObject> value,
                        RelocInfo::Mode rmode) {
  // TODO(jgruber,v8:8887): Also consider a root-relative load when generating
  // non-isolate-independent code. In many cases it might be cheaper than
  // embedding the relocatable value.
  if (root_array_available_ && options().isolate_independent_code) {
    IndirectLoadConstant(dst, value);
    return;
  } else if (RelocInfo::IsCompressedEmbeddedObject(rmode)) {
    EmbeddedObjectIndex index = AddEmbeddedObject(value);
    DCHECK(is_uint32(index));
    li(dst, Operand(index, rmode));
  } else {
    DCHECK(RelocInfo::IsFullEmbeddedObject(rmode));
    li(dst, Operand(value.address(), rmode));
  }
}

void MacroAssembler::li(Register dst, ExternalReference reference,
                        LiFlags mode) {
  if (root_array_available()) {
    if (reference.IsIsolateFieldId()) {
      AddWord(dst, kRootRegister,
              Operand(reference.offset_from_root_register()));
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
  int64_t Hi20 = ((value + 0x800) >> 12);
  int64_t Lo12 = value << 52 >> 52;
  if (Hi20 == 0 || Lo12 == 0) {
    return 1;
  }
  return 2;
}

int MacroAssembler::InstrCountForLi64Bit(int64_t value) {
  if (is_int32(value + 0x800)) {
    return InstrCountForLiLower32Bit(value);
  } else {
    return RV_li_count(value);
  }
  UNREACHABLE();
  return INT_MAX;
}

void MacroAssembler::li_optimized(Register rd, Operand j, LiFlags mode) {
  DCHECK(!j.is_reg());
  DCHECK(!MustUseReg(j.rmode()));
  DCHECK(mode == OPTIMIZE_SIZE);
  Li(rd, j.immediate());
}

void MacroAssembler::li(Register rd, Operand j, LiFlags mode) {
  DCHECK(!j.is_reg());
  BlockTrampolinePoolScope block_trampoline_pool(this);
  if (!MustUseReg(j.rmode()) && mode == OPTIMIZE_SIZE) {
    UseScratchRegisterScope temps(this);
    int count = RV_li_count(j.immediate(), temps.CanAcquire());
    int reverse_count = RV_li_count(~j.immediate(), temps.CanAcquire());
    if (v8_flags.riscv_constant_pool && count >= 4 && reverse_count >= 4) {
      // Ld/Lw an Address from a constant pool.
#if V8_TARGET_ARCH_RISCV32
      RecordEntry((uint32_t)j.immediate(), j.rmode());
#elif V8_TARGET_ARCH_RISCV64
      RecordEntry((uint64_t)j.immediate(), j.rmode());
#endif
      auipc(rd, 0);
      // Record a value into constant pool, passing 1 as the offset makes the
      // promise that LoadWord() generates full 32-bit instruction to be
      // patched with real value in the future
      LoadWord(rd, MemOperand(rd, 1));
    } else {
      if ((count - reverse_count) > 1) {
        Li(rd, ~j.immediate());
        not_(rd, rd);
      } else {
        Li(rd, j.immediate());
      }
    }
  } else if (MustUseReg(j.rmode())) {
    if (RelocInfo::IsWasmCanonicalSigId(j.rmode())) {
      RecordRelocInfo(j.rmode());
      DCHECK(is_int32(j.immediate()));
#if V8_TARGET_ARCH_RISCV64
      li_constant32(rd, int32_t(j.immediate()));
#elif V8_TARGET_ARCH_RISCV32
      li_constant(rd, int32_t(j.immediate()));
#endif
    } else {
      int64_t immediate;
      if (j.IsHeapNumberRequest()) {
        RequestHeapNumber(j.heap_number_request());
        immediate = 0;
      } else {
        immediate = j.immediate();
      }

      RecordRelocInfo(j.rmode(), immediate);
      li_ptr(rd, immediate);
    }
  } else if (mode == ADDRESS_LOAD) {
    // We always need the same number of instructions as we may need to patch
    // this code to load another value which may need all 6 instructions.
    RecordRelocInfo(j.rmode());
    li_ptr(rd, j.immediate());
  } else {  // Always emit the same 48 bit instruction
            // sequence.
    li_ptr(rd, j.immediate());
  }
}

static RegList t_regs = {t0, t1, t2, t3, t4, t5, t6};
static RegList a_regs = {a0, a1, a2, a3, a4, a5, a6, a7};
static RegList s_regs = {s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11};

void MacroAssembler::MultiPush(RegList regs) {
  int16_t num_to_push = regs.Count();
  int16_t stack_offset = num_to_push * kSystemPointerSize;

#define TEST_AND_PUSH_REG(reg)                    \
  if (regs.has(reg)) {                            \
    stack_offset -= kSystemPointerSize;           \
    StoreWord(reg, MemOperand(sp, stack_offset)); \
    regs.clear(reg);                              \
  }

#define T_REGS(V) V(t6) V(t5) V(t4) V(t3) V(t2) V(t1) V(t0)
#define A_REGS(V) V(a7) V(a6) V(a5) V(a4) V(a3) V(a2) V(a1) V(a0)
#define S_REGS(V) \
  V(s11) V(s10) V(s9) V(s8) V(s7) V(s6) V(s5) V(s4) V(s3) V(s2) V(s1)

  SubWord(sp, sp, Operand(stack_offset));

  // Certain usage of MultiPush requires that registers are pushed onto the
  // stack in a particular: ra, fp, sp, gp, .... (basically in the decreasing
  // order of register numbers according to MIPS register numbers)
  TEST_AND_PUSH_REG(ra);
  TEST_AND_PUSH_REG(fp);
  TEST_AND_PUSH_REG(sp);
  TEST_AND_PUSH_REG(gp);
  TEST_AND_PUSH_REG(tp);
  if (!(regs & s_regs).is_empty()) {
    S_REGS(TEST_AND_PUSH_REG)
  }
  if (!(regs & a_regs).is_empty()) {
    A_REGS(TEST_AND_PUSH_REG)
  }
  if (!(regs & t_regs).is_empty()) {
    T_REGS(TEST_AND_PUSH_REG)
  }

  DCHECK(regs.is_empty());

#undef TEST_AND_PUSH_REG
#undef T_REGS
#undef A_REGS
#undef S_REGS
}

void MacroAssembler::MultiPop(RegList regs) {
  int16_t stack_offset = 0;

#define TEST_AND_POP_REG(reg)                    \
  if (regs.has(reg)) {                           \
    LoadWord(reg, MemOperand(sp, stack_offset)); \
    stack_offset += kSystemPointerSize;          \
    regs.clear(reg);                             \
  }

#define T_REGS(V) V(t0) V(t1) V(t2) V(t3) V(t4) V(t5) V(t6)
#define A_REGS(V) V(a0) V(a1) V(a2) V(a3) V(a4) V(a5) V(a6) V(a7)
#define S_REGS(V) \
  V(s1) V(s2) V(s3) V(s4) V(s5) V(s6) V(s7) V(s8) V(s9) V(s10) V(s11)

  // MultiPop pops from the stack in reverse order as MultiPush
  if (!(regs & t_regs).is_empty()) {
    T_REGS(TEST_AND_POP_REG)
  }
  if (!(regs & a_regs).is_empty()) {
    A_REGS(TEST_AND_POP_REG)
  }
  if (!(regs & s_regs).is_empty()) {
    S_REGS(TEST_AND_POP_REG)
  }
  TEST_AND_POP_REG(tp);
  TEST_AND_POP_REG(gp);
  TEST_AND_POP_REG(sp);
  TEST_AND_POP_REG(fp);
  TEST_AND_POP_REG(ra);

  DCHECK(regs.is_empty());

  addi(sp, sp, stack_offset);

#undef TEST_AND_POP_REG
#undef T_REGS
#undef S_REGS
#undef A_REGS
}

void MacroAssembler::MultiPushFPU(DoubleRegList regs) {
  int16_t num_to_push = regs.Count();
  int16_t stack_offset = num_to_push * kDoubleSize;

  SubWord(sp, sp, Operand(stack_offset));
  for (int16_t i = kNumRegisters - 1; i >= 0; i--) {
    if ((regs.bits() & (1 << i)) != 0) {
      stack_offset -= kDoubleSize;
      StoreDouble(FPURegister::from_code(i), MemOperand(sp, stack_offset));
    }
  }
}

void MacroAssembler::MultiPopFPU(DoubleRegList regs) {
  int16_t stack_offset = 0;

  for (int16_t i = 0; i < kNumRegisters; i++) {
    if ((regs.bits() & (1 << i)) != 0) {
      LoadDouble(FPURegister::from_code(i), MemOperand(sp, stack_offset));
      stack_offset += kDoubleSize;
    }
  }
  addi(sp, sp, stack_offset);
}

#if V8_TARGET_ARCH_RISCV32
void MacroAssembler::AddPair(Register dst_low, Register dst_high,
                             Register left_low, Register left_high,
                             Register right_low, Register right_high,
                             Register scratch1, Register scratch2) {
  UseScratchRegisterScope temps(this);
  Register scratch3 = temps.Acquire();
  BlockTrampolinePoolScope block_trampoline_pool(this);

  Add32(scratch1, left_low, right_low);
  // Save the carry
  Sltu(scratch3, scratch1, left_low);
  Add32(scratch2, left_high, right_high);

  // Output higher 32 bits + carry
  Add32(dst_high, scratch2, scratch3);
  Move(dst_low, scratch1);
}

void MacroAssembler::SubPair(Register dst_low, Register dst_high,
                             Register left_low, Register left_high,
                             Register right_low, Register right_high,
                             Register scratch1, Register scratch2) {
  UseScratchRegisterScope temps(this);
  Register scratch3 = temps.Acquire();
  BlockTrampolinePoolScope block_trampoline_pool(this);

  // Check if we need a borrow
  Sltu(scratch3, left_low, right_low);
  Sub32(scratch1, left_low, right_low);
  Sub32(scratch2, left_high, right_high);

  // Output higher 32 bits - borrow
  Sub32(dst_high, scratch2, scratch3);
  Move(dst_low, scratch1);
}

void MacroAssembler::AndPair(Register dst_low, Register dst_high,
                             Register left_low, Register left_high,
                             Register right_low, Register right_high) {
  And(dst_low, left_low, right_low);
  And(dst_high, left_high, right_high);
}

void MacroAssembler::OrPair(Register dst_low, Register dst_high,
                            Register left_low, Register left_high,
                            Register right_low, Register right_high) {
  Or(dst_low, left_low, right_low);
  Or(dst_high, left_high, right_high);
}
void MacroAssembler::XorPair(Register dst_low, Register dst_high,
                             Register left_low, Register left_high,
                             Register right_low, Register right_high) {
  Xor(dst_low, left_low, right_low);
  Xor(dst_high, left_high, right_high);
}

void MacroAssembler::MulPair(Register dst_low, Register dst_high,
                             Register left_low, Register left_high,
                             Register right_low, Register right_high,
                             Register scratch1, Register scratch2) {
  UseScratchRegisterScope temps(this);
  Register scratch3 = temps.Acquire();
  BlockTrampolinePoolScope block_trampoline_pool(this);
  if (dst_low == right_low) {
    mv(scratch1, right_low);
  }
  Mul(scratch3, left_low, right_high);
  // NOTE: do not move these around, recommended sequence is MULH-MUL
  // LL * RL : higher 32 bits
  mulhu(scratch2, left_low, right_low);
  // LL * RL : lower 32 bits
  Mul(dst_low, left_low, right_low);
  // (LL * RH) + (LL * RL : higher 32 bits)
  Add32(scratch2, scratch2, scratch3);
  if (dst_low != right_low) {
    Mul(scratch3, left_high, right_low);
  } else {
    Mul(scratch3, left_high, scratch1);
  }
  Add32(dst_high, scratch2, scratch3);
}

void MacroAssembler::ShlPair(Register dst_low, Register dst_high,
                             Register src_low, Register src_high,
                             Register shift, Register scratch1,
                             Register scratch2) {
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Label done;
  UseScratchRegisterScope temps(this);
  Register scratch3 = no_reg;
  if (dst_low == src_low) {
    scratch3 = temps.Acquire();
    mv(scratch3, src_low);
  }
  And(scratch1, shift, 0x1F);
  // LOW32 << shamt
  sll(dst_low, src_low, scratch1);
  // HIGH32 << shamt
  sll(dst_high, src_high, scratch1);

  // If the shift amount is 0, we're done
  Branch(&done, eq, shift, Operand(zero_reg));

  // LOW32 >> (32 - shamt)
  li(scratch2, 32);
  Sub32(scratch2, scratch2, scratch1);
  if (dst_low == src_low) {
    srl(scratch1, scratch3, scratch2);
  } else {
    srl(scratch1, src_low, scratch2);
  }

  // (HIGH32 << shamt) | (LOW32 >> (32 - shamt))
  Or(dst_high, dst_high, scratch1);

  // 
"""


```