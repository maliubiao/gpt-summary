Response: The user wants a summary of the functionality of the provided C++ code snippet. This is the second part of a larger file. I need to analyze the code and identify the main operations and data structures involved. The code seems to be implementing helper functions for the RISC-V macro assembler, focusing on loading and storing data of various sizes, both aligned and unaligned, and also handling floating-point operations.

Key areas to investigate:
- `LoadNBytes` and `LoadNBytesOverwritingBaseReg`: Loading a specific number of bytes from memory.
- `UnalignedLoadHelper` and `UnalignedStoreHelper`: Handling unaligned memory access.
- `AlignedLoadHelper` and `AlignedStoreHelper`: Handling aligned memory access, possibly with trapping.
- Load/Store functions for different data types (word, half-word, byte, double, float) and their unaligned variants (Ulw, Ulh, etc.).
- Floating-point load/store functions (ULoadFloat, UStoreFloat, etc.).
- Atomic load/store functions (Ll, Sc).
- Functions for loading constants and external references (`li`).
- Multi-push/pop functions for registers and floating-point registers.
- Arithmetic and logical operations on pairs of registers (for 64-bit operations on 32-bit architectures).
- Bit manipulation functions (ExtractBits, InsertBits).
- Floating-point conversion and rounding functions.
- Floating-point comparison functions.
- Branching functions based on register values.

The code also has conditional compilation based on the target architecture (`V8_TARGET_ARCH_RISCV64` and `V8_TARGET_ARCH_RISCV32`), indicating different implementations for 32-bit and 64-bit RISC-V.

Regarding the connection to JavaScript, this code is part of the V8 JavaScript engine. The macro assembler is used to generate native machine code from the intermediate representation of JavaScript code. The load and store operations are essential for accessing JavaScript values in memory, and the floating-point operations are used for numerical computations.
这段C++代码是V8 JavaScript引擎中RISC-V架构的宏汇编器的一部分，主要负责实现以下功能：

**1. 加载和存储多字节数据（LoadNBytes）：**

- 提供了模板函数 `LoadNBytes`，用于从内存中加载指定字节数的数据到寄存器中。
- 它可以选择是否进行符号扩展 (`LOAD_SIGNED`)。
- 它使用移位和或运算来组合多个字节。

**2. 加载和存储非对齐数据（Unaligned Load/Store Helpers）：**

- 提供了 `UnalignedLoadHelper` 和 `UnalignedStoreHelper` 模板函数，用于处理从非对齐内存地址加载和存储数据的情况。
- 这些函数会检查内存操作数是否需要调整基址和偏移量以进行多次访问。
- 针对浮点数，提供了 `UnalignedFLoadHelper` 和 `UnalignedFStoreHelper`，以及针对双精度浮点数的 `UnalignedDoubleHelper` 和 `UnalignedDStoreHelper`。
- 这些助手函数会根据目标架构（RISCV32或RISCV64）进行不同的处理。

**3. 加载和存储对齐数据（Aligned Load/Store Helpers）：**

- 提供了 `AlignedLoadHelper` 和 `AlignedStoreHelper` 模板函数，用于处理从对齐内存地址加载和存储数据的情况。
- 允许传入一个函数对象 (`generator`) 来执行实际的加载/存储指令，从而可以方便地添加额外的操作，例如在加载/存储前插入陷阱指令 (`Trapper`)。

**4. 提供不同数据类型的加载和存储指令的封装：**

- 针对不同的数据类型（字节、半字、字、双字、单精度浮点数、双精度浮点数），提供了相应的加载和存储函数，如 `Ulw`（非对齐加载字）、`Ush`（非对齐存储半字）、`LoadFloat`（加载单精度浮点数）等。
- 这些函数内部会调用相应的对齐或非对齐助手函数。
- 部分函数支持在加载/存储前插入陷阱指令 (`Trapper`)，用于实现一些调试或安全机制。

**5. 原子加载和存储指令的封装：**

- 提供了 `Ll`（Load-Linked，加载并保留）和 `Sc`（Store-Conditional，条件存储）函数，用于实现原子操作。

**6. 加载立即数和外部引用（li）：**

- 提供了 `li` 函数的多个重载版本，用于将立即数或外部引用加载到寄存器中。
- 可以处理不同类型的重定位信息 (`RelocInfo::Mode`)，包括嵌入式对象和外部引用。
- 针对立即数加载进行了优化，会根据立即数的大小选择最优的指令序列。

**7. 多寄存器压栈和出栈（MultiPush/MultiPop）：**

- 提供了 `MultiPush` 和 `MultiPop` 函数，用于将多个通用寄存器压入或弹出栈。
- 提供了 `MultiPushFPU` 和 `MultiPopFPU` 函数，用于将多个浮点寄存器压入或弹出栈。

**8. 32位架构下的64位运算辅助函数：**

- 在 RISCV32 架构下，提供了用于进行 64 位整数运算的辅助函数，例如 `AddPair`（加法）、`SubPair`（减法）、`AndPair`（按位与）、`OrPair`（按位或）、`XorPair`（按位异或）、`MulPair`（乘法）、`ShlPair`（左移）、`ShrPair`（逻辑右移）、`SarPair`（算术右移）。

**9. 位操作函数：**

- 提供了 `ExtractBits` 函数用于从寄存器中提取指定位置和长度的位。
- 提供了 `InsertBits` 函数用于将一个寄存器的值插入到另一个寄存器的指定位置。

**10. 浮点数操作函数：**

- 提供了各种浮点数操作的封装，例如取反 (`Neg_s`, `Neg_d`)、类型转换 (`Cvt_d_uw`, `Cvt_s_w` 等)、舍入到整数 (`Trunc_uw_d`, `Round_w_s` 等)、清除 NaN (`Clear_if_nan_d`, `Clear_if_nan_s`)。
- 提供了更精确的浮点数舍入助手函数 `RoundHelper`，用于处理 JavaScript 中对 NaN、无穷大和零的特殊舍入需求。
- 提供了融合乘法加/减运算 (`Madd_s`, `Msub_d`)。
- 提供了浮点数比较函数 (`CompareF32`, `CompareF64`)，以及判断是否为 NaN 的函数 (`CompareIsNotNanF32`, `CompareIsNanF64`)。

**11. 分支指令的封装：**

- 提供了基于寄存器值进行条件分支的函数，例如 `BranchTrueF` 和 `BranchFalseF`。

**12. 浮点数的高位字插入 (InsertHighWordF64):**

- 提供了将一个通用寄存器中的高位字插入到双精度浮点数寄存器的函数。

**与 JavaScript 的关系示例：**

假设有以下 JavaScript 代码：

```javascript
let a = 10.5;
let b = 5.2;
let c = a + b;
console.log(Math.floor(c));
```

当 V8 引擎执行这段代码时，宏汇编器会生成相应的 RISC-V 汇编指令。  在这个例子中，`macro-assembler-riscv.cc` 中的一些函数可能会被使用：

- **加载浮点数：**  `ULoadDouble` 或 `LoadDouble` 可能被用于将 JavaScript 变量 `a` 和 `b` 的值（以双精度浮点数形式存储）从内存加载到 RISC-V 的浮点寄存器中。例如：
  ```assembly
  // 假设 a 的内存地址在某个 MemOperand 对象中，加载到 f0
  fld f0, [address_of_a]
  // 假设 b 的内存地址在另一个 MemOperand 对象中，加载到 f1
  fld f1, [address_of_b]
  ```

- **浮点数加法：** `Add_d` (在其他部分代码中定义，但与此文件功能相关) 可能被用于执行 `a + b` 的操作。
  ```assembly
  // 将 f0 和 f1 的值相加，结果存储到 f2
  fadd.d f2, f0, f1
  ```

- **浮点数向下取整：** `Floor_d_d` 或 `Floor_d` 可能被用于执行 `Math.floor(c)` 操作。
  ```assembly
  // 将 f2 的值向下取整，结果存储到 f3
  frnd.d.down f3, f2
  ```

- **浮点数到整数的转换：** `Trunc_w_d` 或类似的函数可能被用于将浮点数结果转换为整数以便进行后续的 `console.log` 操作 (假设 console.log 最终需要一个整数)。
  ```assembly
  // 将 f3 的值截断为整数，结果存储到 t0
  fcvt.w.d.rtz t0, f3
  ```

- **存储整数或进一步处理：**  `Sw` 或其他存储指令可能被用于将整数结果存储到内存中，或者传递给用于输出的函数。

**总结：**

这个代码片段是 RISC-V 架构下 V8 引擎的核心组成部分，它提供了构建高效机器码的基础指令和助手函数，用于处理内存访问、数据操作和控制流，从而使得 JavaScript 代码能够在 RISC-V 处理器上高效执行。它专注于底层的指令生成，屏蔽了许多 RISC-V 汇编的细节，为 V8 的其他组件提供了更高级别的抽象。

Prompt: 
```
这是目录为v8/src/codegen/riscv/macro-assembler-riscv.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共5部分，请归纳一下它的功能

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

  // If the shift amount is < 32, we're done
  // Note: the shift amount is always < 64, so we can just test if the 6th bit
  // is set
  And(scratch1, shift, 32);
  Branch(&done, eq, scratch1, Operand(zero_reg));
  Move(dst_high, dst_low);
  Move(dst_low, zero_reg);

  bind(&done);
}

void MacroAssembler::ShlPair(Register dst_low, Register dst_high,
                             Register src_low, Register src_high, int32_t shift,
                             Register scratch1, Register scratch2) {
  DCHECK_GE(63, shift);
  DCHECK_NE(dst_low, src_low);
  DCHECK_NE(dst_high, src_low);
  shift &= 0x3F;
  if (shift == 0) {
    Move(dst_high, src_high);
    Move(dst_low, src_low);
  } else if (shift == 32) {
    Move(dst_high, src_low);
    li(dst_low, Operand(0));
  } else if (shift > 32) {
    shift &= 0x1F;
    slli(dst_high, src_low, shift);
    li(dst_low, Operand(0));
  } else {
    slli(dst_high, src_high, shift);
    slli(dst_low, src_low, shift);
    srli(scratch1, src_low, 32 - shift);
    Or(dst_high, dst_high, scratch1);
  }
}

void MacroAssembler::ShrPair(Register dst_low, Register dst_high,
                             Register src_low, Register src_high,
                             Register shift, Register scratch1,
                             Register scratch2) {
  ASM_CODE_COMMENT(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Label done;
  UseScratchRegisterScope temps(this);
  Register scratch3 = no_reg;
  if (dst_high == src_high) {
    scratch3 = temps.Acquire();
    mv(scratch3, src_high);
  }
  And(scratch1, shift, 0x1F);
  // HIGH32 >> shamt
  srl(dst_high, src_high, scratch1);
  // LOW32 >> shamt
  srl(dst_low, src_low, scratch1);

  // If the shift amount is 0, we're done
  Branch(&done, eq, shift, Operand(zero_reg));

  // HIGH32 << (32 - shamt)
  li(scratch2, 32);
  Sub32(scratch2, scratch2, scratch1);
  if (dst_high == src_high) {
    sll(scratch1, scratch3, scratch2);
  } else {
    sll(scratch1, src_high, scratch2);
  }

  // (HIGH32 << (32 - shamt)) | (LOW32 >> shamt)
  Or(dst_low, dst_low, scratch1);

  // If the shift amount is < 32, we're done
  // Note: the shift amount is always < 64, so we can just test if the 6th bit
  // is set
  And(scratch1, shift, 32);
  Branch(&done, eq, scratch1, Operand(zero_reg));
  Move(dst_low, dst_high);
  Move(dst_high, zero_reg);

  bind(&done);
}

void MacroAssembler::ShrPair(Register dst_low, Register dst_high,
                             Register src_low, Register src_high, int32_t shift,
                             Register scratch1, Register scratch2) {
  DCHECK_GE(63, shift);
  DCHECK_NE(dst_low, src_high);
  DCHECK_NE(dst_high, src_high);
  shift &= 0x3F;
  if (shift == 32) {
    mv(dst_low, src_high);
    li(dst_high, Operand(0));
  } else if (shift > 32) {
    shift &= 0x1F;
    srli(dst_low, src_high, shift);
    li(dst_high, Operand(0));
  } else if (shift == 0) {
    Move(dst_low, src_low);
    Move(dst_high, src_high);
  } else {
    srli(dst_low, src_low, shift);
    srli(dst_high, src_high, shift);
    slli(scratch1, src_high, 32 - shift);
    Or(dst_low, dst_low, scratch1);
  }
}

void MacroAssembler::SarPair(Register dst_low, Register dst_high,
                             Register src_low, Register src_high,
                             Register shift, Register scratch1,
                             Register scratch2) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Label done;
  UseScratchRegisterScope temps(this);
  Register scratch3 = no_reg;
  if (dst_high == src_high) {
    scratch3 = temps.Acquire();
    mv(scratch3, src_high);
  }
  And(scratch1, shift, 0x1F);
  // HIGH32 >> shamt (arithmetic)
  sra(dst_high, src_high, scratch1);
  // LOW32 >> shamt (logical)
  srl(dst_low, src_low, scratch1);

  // If the shift amount is 0, we're done
  Branch(&done, eq, shift, Operand(zero_reg));

  // HIGH32 << (32 - shamt)
  li(scratch2, 32);
  Sub32(scratch2, scratch2, scratch1);
  if (dst_high == src_high) {
    sll(scratch1, scratch3, scratch2);
  } else {
    sll(scratch1, src_high, scratch2);
  }
  // (HIGH32 << (32 - shamt)) | (LOW32 >> shamt)
  Or(dst_low, dst_low, scratch1);

  // If the shift amount is < 32, we're done
  // Note: the shift amount is always < 64, so we can just test if the 6th bit
  // is set
  And(scratch1, shift, 32);
  Branch(&done, eq, scratch1, Operand(zero_reg));
  Move(dst_low, dst_high);
  Sra32(dst_high, dst_high, 31);

  bind(&done);
}

void MacroAssembler::SarPair(Register dst_low, Register dst_high,
                             Register src_low, Register src_high, int32_t shift,
                             Register scratch1, Register scratch2) {
  DCHECK_GE(63, shift);
  DCHECK_NE(dst_low, src_high);
  DCHECK_NE(dst_high, src_high);
  shift = shift & 0x3F;
  if (shift == 0) {
    mv(dst_low, src_low);
    mv(dst_high, src_high);
  } else if (shift < 32) {
    srli(dst_low, src_low, shift);
    srai(dst_high, src_high, shift);
    slli(scratch1, src_high, 32 - shift);
    Or(dst_low, dst_low, scratch1);
  } else if (shift == 32) {
    srai(dst_high, src_high, 31);
    mv(dst_low, src_high);
  } else {
    srai(dst_high, src_high, 31);
    srai(dst_low, src_high, shift - 32);
  }
}
#endif

void MacroAssembler::ExtractBits(Register rt, Register rs, uint16_t pos,
                                 uint16_t size, bool sign_extend) {
#if V8_TARGET_ARCH_RISCV64
  DCHECK(pos < 64 && 0 < size && size <= 64 && 0 < pos + size &&
         pos + size <= 64);
  slli(rt, rs, 64 - (pos + size));
  if (sign_extend) {
    srai(rt, rt, 64 - size);
  } else {
    srli(rt, rt, 64 - size);
  }
#elif V8_TARGET_ARCH_RISCV32
  DCHECK_LT(pos, 32);
  DCHECK_GT(size, 0);
  DCHECK_LE(size, 32);
  DCHECK_GT(pos + size, 0);
  DCHECK_LE(pos + size, 32);
  slli(rt, rs, 32 - (pos + size));
  if (sign_extend) {
    srai(rt, rt, 32 - size);
  } else {
    srli(rt, rt, 32 - size);
  }
#endif
}

void MacroAssembler::InsertBits(Register dest, Register source, Register pos,
                                int size) {
#if V8_TARGET_ARCH_RISCV64
  DCHECK_LT(size, 64);
#elif V8_TARGET_ARCH_RISCV32
  DCHECK_LT(size, 32);
#endif
  UseScratchRegisterScope temps(this);
  Register mask = temps.Acquire();
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register source_ = temps.Acquire();
  // Create a mask of the length=size.
  li(mask, 1);
  slli(mask, mask, size);
  addi(mask, mask, -1);
  and_(source_, mask, source);
  sll(source_, source_, pos);
  // Make a mask containing 0's. 0's start at "pos" with length=size.
  sll(mask, mask, pos);
  not_(mask, mask);
  // cut area for insertion of source.
  and_(dest, mask, dest);
  // insert source
  or_(dest, dest, source_);
}

void MacroAssembler::Neg_s(FPURegister fd, FPURegister fs) { fneg_s(fd, fs); }

void MacroAssembler::Neg_d(FPURegister fd, FPURegister fs) { fneg_d(fd, fs); }

void MacroAssembler::Cvt_d_uw(FPURegister fd, Register rs) {
  // Convert rs to a FP value in fd.
  fcvt_d_wu(fd, rs);
}

void MacroAssembler::Cvt_d_w(FPURegister fd, Register rs) {
  // Convert rs to a FP value in fd.
  fcvt_d_w(fd, rs);
}
#if V8_TARGET_ARCH_RISCV64
void MacroAssembler::Cvt_d_ul(FPURegister fd, Register rs) {
  // Convert rs to a FP value in fd.
  fcvt_d_lu(fd, rs);
}
#endif
void MacroAssembler::Cvt_s_uw(FPURegister fd, Register rs) {
  // Convert rs to a FP value in fd.
  fcvt_s_wu(fd, rs);
}

void MacroAssembler::Cvt_s_w(FPURegister fd, Register rs) {
  // Convert rs to a FP value in fd.
  fcvt_s_w(fd, rs);
}
#if V8_TARGET_ARCH_RISCV64
void MacroAssembler::Cvt_s_ul(FPURegister fd, Register rs) {
  // Convert rs to a FP value in fd.
  fcvt_s_lu(fd, rs);
}
#endif
template <typename CvtFunc>
void MacroAssembler::RoundFloatingPointToInteger(Register rd, FPURegister fs,
                                                 Register result,
                                                 CvtFunc fcvt_generator) {
  // Save csr_fflags to scratch & clear exception flags
  if (result.is_valid()) {
    BlockTrampolinePoolScope block_trampoline_pool(this);
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();

    int exception_flags = kInvalidOperation;
    csrrci(scratch, csr_fflags, exception_flags);

    // actual conversion instruction
    fcvt_generator(this, rd, fs);

    // check kInvalidOperation flag (out-of-range, NaN)
    // set result to 1 if normal, otherwise set result to 0 for abnormal
    frflags(result);
    andi(result, result, exception_flags);
    seqz(result, result);  // result <-- 1 (normal), result <-- 0 (abnormal)

    // restore csr_fflags
    csrw(csr_fflags, scratch);
  } else {
    // actual conversion instruction
    fcvt_generator(this, rd, fs);
  }
}

void MacroAssembler::Clear_if_nan_d(Register rd, FPURegister fs) {
  Label no_nan;
  DCHECK_NE(kScratchReg, rd);
  feq_d(kScratchReg, fs, fs);
  bnez(kScratchReg, &no_nan);
  Move(rd, zero_reg);
  bind(&no_nan);
}

void MacroAssembler::Clear_if_nan_s(Register rd, FPURegister fs) {
  Label no_nan;
  DCHECK_NE(kScratchReg, rd);
  feq_s(kScratchReg, fs, fs);
  bnez(kScratchReg, &no_nan);
  Move(rd, zero_reg);
  bind(&no_nan);
}

void MacroAssembler::Trunc_uw_d(Register rd, FPURegister fs, Register result) {
  RoundFloatingPointToInteger(
      rd, fs, result, [](MacroAssembler* masm, Register dst, FPURegister src) {
        masm->fcvt_wu_d(dst, src, RTZ);
      });
}

void MacroAssembler::Trunc_w_d(Register rd, FPURegister fs, Register result) {
  RoundFloatingPointToInteger(
      rd, fs, result, [](MacroAssembler* masm, Register dst, FPURegister src) {
        masm->fcvt_w_d(dst, src, RTZ);
      });
}

void MacroAssembler::Trunc_uw_s(Register rd, FPURegister fs, Register result) {
  RoundFloatingPointToInteger(
      rd, fs, result, [](MacroAssembler* masm, Register dst, FPURegister src) {
        masm->fcvt_wu_s(dst, src, RTZ);
      });
}

void MacroAssembler::Trunc_w_s(Register rd, FPURegister fs, Register result) {
  RoundFloatingPointToInteger(
      rd, fs, result, [](MacroAssembler* masm, Register dst, FPURegister src) {
        masm->fcvt_w_s(dst, src, RTZ);
      });
}
#if V8_TARGET_ARCH_RISCV64
void MacroAssembler::Trunc_ul_d(Register rd, FPURegister fs, Register result) {
  RoundFloatingPointToInteger(
      rd, fs, result, [](MacroAssembler* masm, Register dst, FPURegister src) {
        masm->fcvt_lu_d(dst, src, RTZ);
      });
}

void MacroAssembler::Trunc_l_d(Register rd, FPURegister fs, Register result) {
  RoundFloatingPointToInteger(
      rd, fs, result, [](MacroAssembler* masm, Register dst, FPURegister src) {
        masm->fcvt_l_d(dst, src, RTZ);
      });
}

void MacroAssembler::Trunc_ul_s(Register rd, FPURegister fs, Register result) {
  RoundFloatingPointToInteger(
      rd, fs, result, [](MacroAssembler* masm, Register dst, FPURegister src) {
        masm->fcvt_lu_s(dst, src, RTZ);
      });
}

void MacroAssembler::Trunc_l_s(Register rd, FPURegister fs, Register result) {
  RoundFloatingPointToInteger(
      rd, fs, result, [](MacroAssembler* masm, Register dst, FPURegister src) {
        masm->fcvt_l_s(dst, src, RTZ);
      });
}
#endif
void MacroAssembler::Round_w_s(Register rd, FPURegister fs, Register result) {
  RoundFloatingPointToInteger(
      rd, fs, result, [](MacroAssembler* masm, Register dst, FPURegister src) {
        masm->fcvt_w_s(dst, src, RNE);
      });
}

void MacroAssembler::Round_w_d(Register rd, FPURegister fs, Register result) {
  RoundFloatingPointToInteger(
      rd, fs, result, [](MacroAssembler* masm, Register dst, FPURegister src) {
        masm->fcvt_w_d(dst, src, RNE);
      });
}

void MacroAssembler::Ceil_w_s(Register rd, FPURegister fs, Register result) {
  RoundFloatingPointToInteger(
      rd, fs, result, [](MacroAssembler* masm, Register dst, FPURegister src) {
        masm->fcvt_w_s(dst, src, RUP);
      });
}

void MacroAssembler::Ceil_w_d(Register rd, FPURegister fs, Register result) {
  RoundFloatingPointToInteger(
      rd, fs, result, [](MacroAssembler* masm, Register dst, FPURegister src) {
        masm->fcvt_w_d(dst, src, RUP);
      });
}

void MacroAssembler::Floor_w_s(Register rd, FPURegister fs, Register result) {
  RoundFloatingPointToInteger(
      rd, fs, result, [](MacroAssembler* masm, Register dst, FPURegister src) {
        masm->fcvt_w_s(dst, src, RDN);
      });
}

void MacroAssembler::Floor_w_d(Register rd, FPURegister fs, Register result) {
  RoundFloatingPointToInteger(
      rd, fs, result, [](MacroAssembler* masm, Register dst, FPURegister src) {
        masm->fcvt_w_d(dst, src, RDN);
      });
}

// According to JS ECMA specification, for floating-point round operations, if
// the input is NaN, +/-infinity, or +/-0, the same input is returned as the
// rounded result; this differs from behavior of RISCV fcvt instructions (which
// round out-of-range values to the nearest max or min value), therefore special
// handling is needed by NaN, +/-Infinity, +/-0
#if V8_TARGET_ARCH_RISCV64
template <typename F>
void MacroAssembler::RoundHelper(FPURegister dst, FPURegister src,
                                 FPURegister fpu_scratch, FPURoundingMode frm) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  UseScratchRegisterScope temps(this);
  Register scratch2 = temps.Acquire();

  DCHECK((std::is_same<float, F>::value) || (std::is_same<double, F>::value));
  // Need at least two FPRs, so check against dst == src == fpu_scratch
  DCHECK(!(dst == src && dst == fpu_scratch));

  const int kFloatMantissaBits =
      sizeof(F) == 4 ? kFloat32MantissaBits : kFloat64MantissaBits;
  const int kFloatExponentBits =
      sizeof(F) == 4 ? kFloat32ExponentBits : kFloat64ExponentBits;
  const int kFloatExponentBias =
      sizeof(F) == 4 ? kFloat32ExponentBias : kFloat64ExponentBias;
  Label done;

  {
    UseScratchRegisterScope temps2(this);
    Register scratch = temps2.Acquire();
    // extract exponent value of the source floating-point to scratch
    if (std::is_same<F, double>::value) {
      fmv_x_d(scratch, src);
    } else {
      fmv_x_w(scratch, src);
    }
    ExtractBits(scratch2, scratch, kFloatMantissaBits, kFloatExponentBits);
  }

  // if src is NaN/+-Infinity/+-Zero or if the exponent is larger than # of bits
  // in mantissa, the result is the same as src, so move src to dest  (to avoid
  // generating another branch)
  if (dst != src) {
    if (std::is_same<F, double>::value) {
      fmv_d(dst, src);
    } else {
      fmv_s(dst, src);
    }
  }
  {
    Label not_NaN;
    UseScratchRegisterScope temps2(this);
    Register scratch = temps2.Acquire();
    // According to the wasm spec
    // (https://webassembly.github.io/spec/core/exec/numerics.html#aux-nans)
    // if input is canonical NaN, then output is canonical NaN, and if input is
    // any other NaN, then output is any NaN with most significant bit of
    // payload is 1. In RISC-V, feq_d will set scratch to 0 if src is a NaN. If
    // src is not a NaN, branch to the label and do nothing, but if it is,
    // fmin_d will set dst to the canonical NaN.
    if (std::is_same<F, double>::value) {
      feq_d(scratch, src, src);
      bnez(scratch, &not_NaN);
      fmin_d(dst, src, src);
    } else {
      feq_s(scratch, src, src);
      bnez(scratch, &not_NaN);
      fmin_s(dst, src, src);
    }
    bind(&not_NaN);
  }

  // If real exponent (i.e., scratch2 - kFloatExponentBias) is greater than
  // kFloat32MantissaBits, it means the floating-point value has no fractional
  // part, thus the input is already rounded, jump to done. Note that, NaN and
  // Infinity in floating-point representation sets maximal exponent value, so
  // they also satisfy (scratch2 - kFloatExponentBias >= kFloatMantissaBits),
  // and JS round semantics specify that rounding of NaN (Infinity) returns NaN
  // (Infinity), so NaN and Infinity are considered rounded value too.
  Branch(&done, greater_equal, scratch2,
         Operand(kFloatExponentBias + kFloatMantissaBits));

  // Actual rounding is needed along this path

  // old_src holds the original input, needed for the case of src == dst
  FPURegister old_src = src;
  if (src == dst) {
    DCHECK(fpu_scratch != dst);
    Move(fpu_scratch, src);
    old_src = fpu_scratch;
  }

  // Since only input whose real exponent value is less than kMantissaBits
  // (i.e., 23 or 52-bits) falls into this path, the value range of the input
  // falls into that of 23- or 53-bit integers. So we round the input to integer
  // values, then convert them back to floating-point.
  {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    if (std::is_same<F, double>::value) {
      fcvt_l_d(scratch, src, frm);
      fcvt_d_l(dst, scratch, frm);
    } else {
      fcvt_w_s(scratch, src, frm);
      fcvt_s_w(dst, scratch, frm);
    }
  }
  // A special handling is needed if the input is a very small positive/negative
  // number that rounds to zero. JS semantics requires that the rounded result
  // retains the sign of the input, so a very small positive (negative)
  // floating-point number should be rounded to positive (negative) 0.
  // Therefore, we use sign-bit injection to produce +/-0 correctly. Instead of
  // testing for zero w/ a branch, we just insert sign-bit for everyone on this
  // path (this is where old_src is needed)
  if (std::is_same<F, double>::value) {
    fsgnj_d(dst, dst, old_src);
  } else {
    fsgnj_s(dst, dst, old_src);
  }

  bind(&done);
}
#elif V8_TARGET_ARCH_RISCV32
// According to JS ECMA specification, for floating-point round operations, if
// the input is NaN, +/-infinity, or +/-0, the same input is returned as the
// rounded result; this differs from behavior of RISCV fcvt instructions (which
// round out-of-range values to the nearest max or min value), therefore special
// handling is needed by NaN, +/-Infinity, +/-0
void MacroAssembler::RoundFloat(FPURegister dst, FPURegister src,
                                FPURegister fpu_scratch, FPURoundingMode frm) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  UseScratchRegisterScope temps(this);
  Register scratch2 = temps.Acquire();

  // Need at least two FPRs, so check against dst == src == fpu_scratch
  DCHECK(!(dst == src && dst == fpu_scratch));

  const int kFloatMantissaBits = kFloat32MantissaBits;
  const int kFloatExponentBits = kFloat32ExponentBits;
  const int kFloatExponentBias = kFloat32ExponentBias;
  Label done;

  {
    UseScratchRegisterScope temps2(this);
    Register scratch = temps2.Acquire();
    // extract exponent value of the source floating-point to scratch
    fmv_x_w(scratch, src);
    ExtractBits(scratch2, scratch, kFloatMantissaBits, kFloatExponentBits);
  }

  // if src is NaN/+-Infinity/+-Zero or if the exponent is larger than # of bits
  // in mantissa, the result is the same as src, so move src to dest  (to avoid
  // generating another branch)
  if (dst != src) {
    fmv_s(dst, src);
  }
  {
    Label not_NaN;
    UseScratchRegisterScope temps2(this);
    Register scratch = temps2.Acquire();
    // According to the wasm spec
    // (https://webassembly.github.io/spec/core/exec/numerics.html#aux-nans)
    // if input is canonical NaN, then output is canonical NaN, and if input is
    // any other NaN, then output is any NaN with most significant bit of
    // payload is 1. In RISC-V, feq_d will set scratch to 0 if src is a NaN. If
    // src is not a NaN, branch to the label and do nothing, but if it is,
    // fmin_d will set dst to the canonical NaN.
    feq_s(scratch, src, src);
    bnez(scratch, &not_NaN);
    fmin_s(dst, src, src);
    bind(&not_NaN);
  }

  // If real exponent (i.e., scratch2 - kFloatExponentBias) is greater than
  // kFloat32MantissaBits, it means the floating-point value has no fractional
  // part, thus the input is already rounded, jump to done. Note that, NaN and
  // Infinity in floating-point representation sets maximal exponent value, so
  // they also satisfy (scratch2 - kFloatExponentBias >= kFloatMantissaBits),
  // and JS round semantics specify that rounding of NaN (Infinity) returns NaN
  // (Infinity), so NaN and Infinity are considered rounded value too.
  Branch(&done, greater_equal, scratch2,
         Operand(kFloatExponentBias + kFloatMantissaBits));

  // Actual rounding is needed along this path

  // old_src holds the original input, needed for the case of src == dst
  FPURegister old_src = src;
  if (src == dst) {
    DCHECK(fpu_scratch != dst);
    Move(fpu_scratch, src);
    old_src = fpu_scratch;
  }

  // Since only input whose real exponent value is less than kMantissaBits
  // (i.e., 23 or 52-bits) falls into this path, the value range of the input
  // falls into that of 23- or 53-bit integers. So we round the input to integer
  // values, then convert them back to floating-point.
  {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    fcvt_w_s(scratch, src, frm);
    fcvt_s_w(dst, scratch, frm);
  }
  // A special handling is needed if the input is a very small positive/negative
  // number that rounds to zero. JS semantics requires that the rounded result
  // retains the sign of the input, so a very small positive (negative)
  // floating-point number should be rounded to positive (negative) 0.
  // Therefore, we use sign-bit injection to produce +/-0 correctly. Instead of
  // testing for zero w/ a branch, we just insert sign-bit for everyone on this
  // path (this is where old_src is needed)
  fsgnj_s(dst, dst, old_src);

  bind(&done);
}
#endif  // V8_TARGET_ARCH_RISCV32
// According to JS ECMA specification, for floating-point round operations, if
// the input is NaN, +/-infinity, or +/-0, the same input is returned as the
// rounded result; this differs from behavior of RISCV fcvt instructions (which
// round out-of-range values to the nearest max or min value), therefore special
// handling is needed by NaN, +/-Infinity, +/-0
template <typename F>
void MacroAssembler::RoundHelper(VRegister dst, VRegister src, Register scratch,
                                 VRegister v_scratch, FPURoundingMode frm,
                                 bool keep_nan_same) {
  VU.set(scratch, std::is_same<F, float>::value ? E32 : E64, m1);
  // if src is NaN/+-Infinity/+-Zero or if the exponent is larger than # of bits
  // in mantissa, the result is the same as src, so move src to dest  (to avoid
  // generating another branch)

  // If real exponent (i.e., scratch2 - kFloatExponentBias) is greater than
  // kFloat32MantissaBits, it means the floating-point value has no fractional
  // part, thus the input is already rounded, jump to done. Note that, NaN and
  // Infinity in floating-point representation sets maximal exponent value, so
  // they also satisfy (scratch2 - kFloatExponentBias >= kFloatMantissaBits),
  // and JS round semantics specify that rounding of NaN (Infinity) returns NaN
  // (Infinity), so NaN and Infinity are considered rounded value too.
  const int kFloatMantissaBits =
      sizeof(F) == 4 ? kFloat32MantissaBits : kFloat64MantissaBits;
  const int kFloatExponentBits =
      sizeof(F) == 4 ? kFloat32ExponentBits : kFloat64ExponentBits;
  const int kFloatExponentBias =
      sizeof(F) == 4 ? kFloat32ExponentBias : kFloat64ExponentBias;

  // slli(rt, rs, 64 - (pos + size));
  // if (sign_extend) {
  //   srai(rt, rt, 64 - size);
  // } else {
  //   srli(rt, rt, 64 - size);
  // }
  vmv_vx(v_scratch, zero_reg);
  li(scratch, 64 - kFloatMantissaBits - kFloatExponentBits);
  vsll_vx(v_scratch, src, scratch);
  li(scratch, 64 - kFloatExponentBits);
  vsrl_vx(v_scratch, v_scratch, scratch);
  li(scratch, kFloatExponentBias + kFloatMantissaBits);
  vmslt_vx(v0, v_scratch, scratch);
  VU.set(frm);
  vmv_vv(dst, src);
  if (dst == src) {
    vmv_vv(v_scratch, src);
  }
  vfcvt_x_f_v(dst, src, MaskType::Mask);
  vfcvt_f_x_v(dst, dst, MaskType::Mask);

  // A special handling is needed if the input is a very small positive/negative
  // number that rounds to zero. JS semantics requires that the rounded result
  // retains the sign of the input, so a very small positive (negative)
  // floating-point number should be rounded to positive (negative) 0.
  if (dst == src) {
    vfsngj_vv(dst, dst, v_scratch);
  } else {
    vfsngj_vv(dst, dst, src);
  }
  if (!keep_nan_same) {
    vmfeq_vv(v0, src, src);
    vnot_vv(v0, v0);
    if (std::is_same<F, float>::value) {
      fmv_w_x(kScratchDoubleReg, zero_reg);
    } else {
#ifdef V8_TARGET_ARCH_RISCV64
      fmv_d_x(kScratchDoubleReg, zero_reg);
#elif V8_TARGET_ARCH_RISCV32
      fcvt_d_w(kScratchDoubleReg, zero_reg);
#endif
    }
    vfadd_vf(dst, src, kScratchDoubleReg, MaskType::Mask);
  }
}

void MacroAssembler::Ceil_f(VRegister vdst, VRegister vsrc, Register scratch,
                            VRegister v_scratch) {
  RoundHelper<float>(vdst, vsrc, scratch, v_scratch, RUP, false);
}

void MacroAssembler::Ceil_d(VRegister vdst, VRegister vsrc, Register scratch,
                            VRegister v_scratch) {
  RoundHelper<double>(vdst, vsrc, scratch, v_scratch, RUP, false);
}

void MacroAssembler::Floor_f(VRegister vdst, VRegister vsrc, Register scratch,
                             VRegister v_scratch) {
  RoundHelper<float>(vdst, vsrc, scratch, v_scratch, RDN, false);
}

void MacroAssembler::Floor_d(VRegister vdst, VRegister vsrc, Register scratch,
                             VRegister v_scratch) {
  RoundHelper<double>(vdst, vsrc, scratch, v_scratch, RDN, false);
}

void MacroAssembler::Trunc_d(VRegister vdst, VRegister vsrc, Register scratch,
                             VRegister v_scratch) {
  RoundHelper<double>(vdst, vsrc, scratch, v_scratch, RTZ, false);
}

void MacroAssembler::Trunc_f(VRegister vdst, VRegister vsrc, Register scratch,
                             VRegister v_scratch) {
  RoundHelper<float>(vdst, vsrc, scratch, v_scratch, RTZ, false);
}

void MacroAssembler::Round_f(VRegister vdst, VRegister vsrc, Register scratch,
                             VRegister v_scratch) {
  RoundHelper<float>(vdst, vsrc, scratch, v_scratch, RNE, false);
}

void MacroAssembler::Round_d(VRegister vdst, VRegister vsrc, Register scratch,
                             VRegister v_scratch) {
  RoundHelper<double>(vdst, vsrc, scratch, v_scratch, RNE, false);
}

#if V8_TARGET_ARCH_RISCV64
void MacroAssembler::Floor_d_d(FPURegister dst, FPURegister src,
                               FPURegister fpu_scratch) {
  RoundHelper<double>(dst, src, fpu_scratch, RDN);
}

void MacroAssembler::Ceil_d_d(FPURegister dst, FPURegister src,
                              FPURegister fpu_scratch) {
  RoundHelper<double>(dst, src, fpu_scratch, RUP);
}

void MacroAssembler::Trunc_d_d(FPURegister dst, FPURegister src,
                               FPURegister fpu_scratch) {
  RoundHelper<double>(dst, src, fpu_scratch, RTZ);
}

void MacroAssembler::Round_d_d(FPURegister dst, FPURegister src,
                               FPURegister fpu_scratch) {
  RoundHelper<double>(dst, src, fpu_scratch, RNE);
}
#endif

void MacroAssembler::Floor_s_s(FPURegister dst, FPURegister src,
                               FPURegister fpu_scratch) {
#if V8_TARGET_ARCH_RISCV64
  RoundHelper<float>(dst, src, fpu_scratch, RDN);
#elif V8_TARGET_ARCH_RISCV32
  RoundFloat(dst, src, fpu_scratch, RDN);
#endif
}

void MacroAssembler::Ceil_s_s(FPURegister dst, FPURegister src,
                              FPURegister fpu_scratch) {
#if V8_TARGET_ARCH_RISCV64
  RoundHelper<float>(dst, src, fpu_scratch, RUP);
#elif V8_TARGET_ARCH_RISCV32
  RoundFloat(dst, src, fpu_scratch, RUP);
#endif
}

void MacroAssembler::Trunc_s_s(FPURegister dst, FPURegister src,
                               FPURegister fpu_scratch) {
#if V8_TARGET_ARCH_RISCV64
  RoundHelper<float>(dst, src, fpu_scratch, RTZ);
#elif V8_TARGET_ARCH_RISCV32
  RoundFloat(dst, src, fpu_scratch, RTZ);
#endif
}

void MacroAssembler::Round_s_s(FPURegister dst, FPURegister src,
                               FPURegister fpu_scratch) {
#if V8_TARGET_ARCH_RISCV64
  RoundHelper<float>(dst, src, fpu_scratch, RNE);
#elif V8_TARGET_ARCH_RISCV32
  RoundFloat(dst, src, fpu_scratch, RNE);
#endif
}

void MacroAssembler::Madd_s(FPURegister fd, FPURegister fr, FPURegister fs,
                            FPURegister ft) {
  fmadd_s(fd, fs, ft, fr);
}

void MacroAssembler::Madd_d(FPURegister fd, FPURegister fr, FPURegister fs,
                            FPURegister ft) {
  fmadd_d(fd, fs, ft, fr);
}

void MacroAssembler::Msub_s(FPURegister fd, FPURegister fr, FPURegister fs,
                            FPURegister ft) {
  fmsub_s(fd, fs, ft, fr);
}

void MacroAssembler::Msub_d(FPURegister fd, FPURegister fr, FPURegister fs,
                            FPURegister ft) {
  fmsub_d(fd, fs, ft, fr);
}

void MacroAssembler::CompareF32(Register rd, FPUCondition cc, FPURegister cmp1,
                                FPURegister cmp2) {
  switch (cc) {
    case EQ:
      feq_s(rd, cmp1, cmp2);
      break;
    case NE:
      feq_s(rd, cmp1, cmp2);
      NegateBool(rd, rd);
      break;
    case LT:
      flt_s(rd, cmp1, cmp2);
      break;
    case GE:
      fle_s(rd, cmp2, cmp1);
      break;
    case LE:
      fle_s(rd, cmp1, cmp2);
      break;
    case GT:
      flt_s(rd, cmp2, cmp1);
      break;
    default:
      UNREACHABLE();
  }
}

void MacroAssembler::CompareF64(Register rd, FPUCondition cc, FPURegister cmp1,
                                FPURegister cmp2) {
  switch (cc) {
    case EQ:
      feq_d(rd, cmp1, cmp2);
      break;
    case NE:
      feq_d(rd, cmp1, cmp2);
      NegateBool(rd, rd);
      break;
    case LT:
      flt_d(rd, cmp1, cmp2);
      break;
    case GE:
      fle_d(rd, cmp2, cmp1);
      break;
    case LE:
      fle_d(rd, cmp1, cmp2);
      break;
    case GT:
      flt_d(rd, cmp2, cmp1);
      break;
    default:
      UNREACHABLE();
  }
}

void MacroAssembler::CompareIsNotNanF32(Register rd, FPURegister cmp1,
                                        FPURegister cmp2) {
  UseScratchRegisterScope temps(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register scratch = temps.Acquire();

  feq_s(rd, cmp1, cmp1);       // rd <- !isNan(cmp1)
  feq_s(scratch, cmp2, cmp2);  // scratch <- !isNaN(cmp2)
  And(rd, rd, scratch);        // rd <- !isNan(cmp1) && !isNan(cmp2)
}

void MacroAssembler::CompareIsNotNanF64(Register rd, FPURegister cmp1,
                                        FPURegister cmp2) {
  UseScratchRegisterScope temps(this);
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Register scratch = temps.Acquire();

  feq_d(rd, cmp1, cmp1);       // rd <- !isNan(cmp1)
  feq_d(scratch, cmp2, cmp2);  // scratch <- !isNaN(cmp2)
  And(rd, rd, scratch);        // rd <- !isNan(cmp1) && !isNan(cmp2)
}

void MacroAssembler::CompareIsNanF32(Register rd, FPURegister cmp1,
                                     FPURegister cmp2) {
  CompareIsNotNanF32(rd, cmp1, cmp2);  // rd <- !isNan(cmp1) && !isNan(cmp2)
  Xor(rd, rd, 1);                      // rd <- isNan(cmp1) || isNan(cmp2)
}

void MacroAssembler::CompareIsNanF64(Register rd, FPURegister cmp1,
                                     FPURegister cmp2) {
  CompareIsNotNanF64(rd, cmp1, cmp2);  // rd <- !isNan(cmp1) && !isNan(cmp2)
  Xor(rd, rd, 1);                      // rd <- isNan(cmp1) || isNan(cmp2)
}

void MacroAssembler::BranchTrueShortF(Register rs, Label* target) {
  Branch(target, not_equal, rs, Operand(zero_reg));
}

void MacroAssembler::BranchFalseShortF(Register rs, Label* target) {
  Branch(target, equal, rs, Operand(zero_reg));
}

void MacroAssembler::BranchTrueF(Register rs, Label* target) {
  bool long_branch =
      target->is_bound() ? !is_near(target) : is_trampoline_emitted();
  if (long_branch) {
    Label skip;
    BranchFalseShortF(rs, &skip);
    BranchLong(target);
    bind(&skip);
  } else {
    BranchTrueShortF(rs, target);
  }
}

void MacroAssembler::BranchFalseF(Register rs, Label* target) {
  bool long_branch =
      target->is_bound() ? !is_near(target) : is_trampoline_emitted();
  if (long_branch) {
    Label skip;
    BranchTrueShortF(rs, &skip);
    BranchLong(target);
    bind(&skip);
  } else {
    BranchFalseShortF(rs, target);
  }
}

void MacroAssembler::InsertHighWordF64(FPURegister dst, Register src_high) {
#if V8_TARGET_ARCH_RISCV64
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  Register scratch2 = temps.Acquire();
  BlockTrampolinePoolScope block_trampoline_pool(this);

  DCHECK(src_high != scratch2 && src_high != scratch);

  fmv_x_d(scratch, dst);
  slli(scratch2, src_high, 32);
  slli(scratch, scratch, 32);
  srli(scratch, scratch, 32);
  or_(scratch, scratch, scratch2);
  fmv_d_x(dst, scratch);
#elif V8_TARGET_ARCH_RISCV32
  BlockTrampolinePoolScope block_trampoline_pool(this);
  Add32(sp, sp,
"""


```