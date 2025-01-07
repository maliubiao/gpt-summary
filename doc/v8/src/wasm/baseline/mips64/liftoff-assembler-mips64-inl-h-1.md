Response:
The user wants a summary of the functionality of the provided C++ header file snippet for the V8 JavaScript engine.

The file `v8/src/wasm/baseline/mips64/liftoff-assembler-mips64-inl.h` seems to contain inline implementations for the `LiftoffAssembler` class on the MIPS64 architecture.

Here's a breakdown of the code and its functionalities:

1. **Atomic Operations:** It defines functions for atomic memory operations like `AtomicExchange` and `AtomicCompareExchange`. These operations ensure that memory updates are done in a thread-safe manner.

2. **Stack Frame Management:**  It includes functions for loading and storing values from the caller's stack frame (`LoadCallerFrameSlot`, `StoreCallerFrameSlot`) and the return stack (`LoadReturnStackSlot`).

3. **Data Movement:** Functions like `MoveStackValue`, `Move`, `Spill`, and `Fill` handle moving data between registers and memory (stack).

4. **Integer Arithmetic and Logic:**  It provides inline implementations for various integer operations like addition, subtraction, multiplication, division, bitwise operations (AND, OR, XOR), shifts, and counting leading/trailing zeros and set bits.

5. **Floating-Point Arithmetic:**  It includes functions for floating-point operations like negation, min, max, copysign, addition, subtraction, multiplication, division, absolute value, ceiling, floor, truncation, rounding, and square root.

6. **Type Conversions:** It defines logic for converting between different data types (integers and floating-point numbers). It also handles potential traps during these conversions (e.g., overflow).

Based on this analysis, I can now provide a concise summary of the file's functionality.
这是 `v8/src/wasm/baseline/mips64/liftoff-assembler-mips64-inl.h` 文件的一部分代码片段，主要定义了 `LiftoffAssembler` 类在 MIPS64 架构上的内联函数实现，用于生成 WebAssembly 代码的汇编指令。以下是对这些代码片段功能的归纳：

**功能归纳:**

这段代码片段主要实现了以下功能，用于在 MIPS64 架构上构建 WebAssembly 代码：

1. **原子操作:** 提供了原子交换 (`AtomicExchange`) 和原子比较交换 (`AtomicCompareExchange`) 操作的实现。这些操作用于在多线程环境中安全地修改共享内存。
2. **栈帧操作:** 包含了加载和存储调用者栈帧槽位 (`LoadCallerFrameSlot`, `StoreCallerFrameSlot`) 以及返回栈槽位 (`LoadReturnStackSlot`) 的功能。
3. **数据移动:** 提供了在栈上移动数据 (`MoveStackValue`)，在寄存器之间移动数据 (`Move`)，以及将寄存器数据保存到栈上 (`Spill`) 和从栈上加载数据到寄存器 (`Fill`) 的功能。
4. **整数运算:** 实现了各种整数运算，包括递增 Smi (`IncrementSmi`)，以及 i32 和 i64 类型的乘法 (`emit_i32_mul`, `emit_i64_mul`)、有符号和无符号除法 (`emit_i32_divs`, `emit_i32_divu`, `emit_i64_divs`, `emit_i64_divu`)、有符号和无符号求余 (`emit_i32_rems`, `emit_i32_remu`, `emit_i64_rems`, `emit_i64_remu`)、加减与或非等基本算术和逻辑运算。
5. **位操作:** 提供了计算前导零 (`emit_i32_clz`, `emit_i64_clz`)、尾部零 (`emit_i32_ctz`, `emit_i64_ctz`) 以及人口计数 (设置的位数) (`emit_i32_popcnt`, `emit_i64_popcnt`) 的功能。
6. **移位操作:** 实现了 i32 和 i64 类型的左移 (`shl`)、算术右移 (`sar`) 和逻辑右移 (`shr`) 操作。
7. **类型转换:** 提供了多种类型转换操作的实现 (`emit_type_conversion`)，包括整数类型之间的转换，浮点数类型之间的转换，以及整数和浮点数之间的转换。这些转换操作中还包含了对可能发生的陷阱情况的处理。
8. **浮点数运算:**  包含了对 f32 和 f64 类型的浮点数进行运算的功能，例如取反 (`emit_f32_neg`, `emit_f64_neg`)、取最小值 (`emit_f32_min`, `emit_f64_min`)、取最大值 (`emit_f32_max`, `emit_f64_max`)、复制符号位 (`emit_f32_copysign`, `emit_f64_copysign`)、加减乘除、绝对值、ceil、floor、trunc、nearest int 和平方根等。
9. **填充零:** 提供了用零填充栈槽位的功能 (`FillStackSlotsWithZero`)。
10. **加载地址:** 提供了加载栈上特定偏移地址的功能 (`LoadSpillAddress`).
11. **原子 Fence:** 提供了内存屏障指令 (`AtomicFence`)，确保内存操作的顺序性。

**关于文件类型和 JavaScript 关系：**

根据您的描述，由于该文件以 `.h` 结尾，它是一个 C++ 头文件，而不是 Torque 源文件。它与 JavaScript 的功能有关系，因为它定义了 V8 引擎中执行 WebAssembly 代码的核心组件之一：Liftoff 编译器在 MIPS64 架构上的汇编指令生成。WebAssembly 代码最终会在 JavaScript 引擎中执行。

**代码逻辑推理示例：**

假设输入以下场景来分析 `AtomicCompareExchange` 的代码逻辑：

*   `dst_addr` 寄存器包含内存地址 `0x1000`.
*   `offset_imm` 立即数为 `0`.
*   `expected` LiftoffRegister 对应的值为 `10`.
*   `new_value` LiftoffRegister 对应的值为 `20`.
*   `result` LiftoffRegister 用于存储加载的原始值。
*   `type` 为 `StoreType::kI32Store`.

**执行流程：**

1. 计算目标内存地址，这里是 `0x1000 + 0 = 0x1000`。
2. 进入 `do...while` 循环。
3. 执行 `sync()` 保证内存操作的顺序性。
4. `load_linked(result.gp(), MemOperand(temp0, 0))`：从地址 `0x1000` 原子加载一个 32 位值到 `result` 寄存器。 假设此时内存地址 `0x1000` 的值为 `10`。
5. `BranchShort(&exit, ne, expected.gp(), Operand(result.gp()))`：比较 `expected` 的值 (10) 和加载的值 (10)。由于相等，条件不成立，不跳转到 `exit`。
6. `mov(temp2, new_value.gp())`：将 `new_value` 的值 (20) 移动到 `temp2` 寄存器。
7. `store_conditional(temp2, MemOperand(temp0, 0))`：尝试将 `temp2` 的值 (20) 原子地存储回地址 `0x1000`。由于加载后内存没有被其他线程修改，存储成功，`temp2` 不会是零。
8. `BranchShort(&compareExchange, eq, temp2, Operand(zero_reg))`：检查 `temp2` 是否为零。由于不为零，不跳转回 `compareExchange`，循环结束。
9. 执行 `sync()`。

**输出：**

*   `result` 寄存器包含原始值 `10`。
*   内存地址 `0x1000` 的值被更新为 `20`。

**用户常见的编程错误示例：**

在使用原子操作时，一个常见的错误是**缺乏同步**。例如，在一个线程中使用了 `AtomicExchange` 或 `AtomicCompareExchange`，但在另一个线程中直接读取或写入相同的内存地址而没有适当的同步机制（如互斥锁、信号量或其他原子操作），这可能导致数据竞争和未定义的行为。

**JavaScript 示例（概念性）：**

虽然这段 C++ 代码直接操作汇编指令，但其背后的功能与 JavaScript 中涉及并发和共享内存的场景相关。例如，SharedArrayBuffer 和 Atomics API 提供了在 JavaScript 中进行原子操作的能力。

```javascript
// JavaScript 中使用 SharedArrayBuffer 和 Atomics 的概念性示例
const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 1);
const view = new Int32Array(sab);

// 线程 1
Atomics.compareExchange(view, 0, 10, 20); // 如果 view[0] 是 10，则设置为 20，返回原始值

// 线程 2
console.log(view[0]); // 可能读取到 10 或 20，取决于线程执行顺序和同步
```

这段 JavaScript 代码展示了原子比较交换操作的概念，它与 C++ 代码中的 `AtomicCompareExchange` 功能类似。

总而言之，这段 C++ 代码是 V8 引擎 Liftoff 编译器的核心部分，负责在 MIPS64 架构上生成执行 WebAssembly 代码所需的低级指令，涵盖了原子操作、栈管理、数据移动、整数和浮点数运算以及类型转换等关键功能。

Prompt: 
```
这是目录为v8/src/wasm/baseline/mips64/liftoff-assembler-mips64-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/mips64/liftoff-assembler-mips64-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共5部分，请归纳一下它的功能

"""
          \
    InsertBits(temp2, value.gp(), temp1, size);                              \
    store_conditional(temp2, MemOperand(temp0, 0));                          \
    BranchShort(&exchange, eq, temp2, Operand(zero_reg));                    \
    sync();                                                                  \
  } while (0)

void LiftoffAssembler::AtomicExchange(Register dst_addr, Register offset_reg,
                                      uintptr_t offset_imm,
                                      LiftoffRegister value,
                                      LiftoffRegister result, StoreType type,
                                      bool i64_offset) {
  LiftoffRegList pinned{dst_addr, value, result};
  if (offset_reg != no_reg) pinned.set(offset_reg);
  Register temp0 = pinned.set(GetUnusedRegister(kGpReg, pinned)).gp();
  Register temp1 = pinned.set(GetUnusedRegister(kGpReg, pinned)).gp();
  Register temp2 = pinned.set(GetUnusedRegister(kGpReg, pinned)).gp();
  MemOperand dst_op =
      liftoff::GetMemOp(this, dst_addr, offset_reg, offset_imm, i64_offset);
  Daddu(temp0, dst_op.rm(), dst_op.offset());
  switch (type.value()) {
    case StoreType::kI64Store8:
      ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(Lld, Scd, 8, 7);
      break;
    case StoreType::kI32Store8:
      ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(Ll, Sc, 8, 3);
      break;
    case StoreType::kI64Store16:
      ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(Lld, Scd, 16, 7);
      break;
    case StoreType::kI32Store16:
      ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(Ll, Sc, 16, 3);
      break;
    case StoreType::kI64Store32:
      ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(Lld, Scd, 32, 7);
      break;
    case StoreType::kI32Store:
      ASSEMBLE_ATOMIC_EXCHANGE_INTEGER(Ll, Sc);
      break;
    case StoreType::kI64Store:
      ASSEMBLE_ATOMIC_EXCHANGE_INTEGER(Lld, Scd);
      break;
    default:
      UNREACHABLE();
  }
}
#undef ASSEMBLE_ATOMIC_EXCHANGE_INTEGER
#undef ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT

#define ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER(load_linked,       \
                                                 store_conditional) \
  do {                                                              \
    Label compareExchange;                                          \
    Label exit;                                                     \
    sync();                                                         \
    bind(&compareExchange);                                         \
    load_linked(result.gp(), MemOperand(temp0, 0));                 \
    BranchShort(&exit, ne, expected.gp(), Operand(result.gp()));    \
    mov(temp2, new_value.gp());                                     \
    store_conditional(temp2, MemOperand(temp0, 0));                 \
    BranchShort(&compareExchange, eq, temp2, Operand(zero_reg));    \
    bind(&exit);                                                    \
    sync();                                                         \
  } while (0)

#define ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(            \
    load_linked, store_conditional, size, aligned)               \
  do {                                                           \
    Label compareExchange;                                       \
    Label exit;                                                  \
    andi(temp1, temp0, aligned);                                 \
    Dsubu(temp0, temp0, Operand(temp1));                         \
    sll(temp1, temp1, 3);                                        \
    sync();                                                      \
    bind(&compareExchange);                                      \
    load_linked(temp2, MemOperand(temp0, 0));                    \
    ExtractBits(result.gp(), temp2, temp1, size, false);         \
    ExtractBits(temp2, expected.gp(), zero_reg, size, false);    \
    BranchShort(&exit, ne, temp2, Operand(result.gp()));         \
    InsertBits(temp2, new_value.gp(), temp1, size);              \
    store_conditional(temp2, MemOperand(temp0, 0));              \
    BranchShort(&compareExchange, eq, temp2, Operand(zero_reg)); \
    bind(&exit);                                                 \
    sync();                                                      \
  } while (0)

void LiftoffAssembler::AtomicCompareExchange(
    Register dst_addr, Register offset_reg, uintptr_t offset_imm,
    LiftoffRegister expected, LiftoffRegister new_value, LiftoffRegister result,
    StoreType type, bool i64_offset) {
  LiftoffRegList pinned{dst_addr, expected, new_value, result};
  if (offset_reg != no_reg) pinned.set(offset_reg);
  Register temp0 = pinned.set(GetUnusedRegister(kGpReg, pinned)).gp();
  Register temp1 = pinned.set(GetUnusedRegister(kGpReg, pinned)).gp();
  Register temp2 = pinned.set(GetUnusedRegister(kGpReg, pinned)).gp();
  MemOperand dst_op =
      liftoff::GetMemOp(this, dst_addr, offset_reg, offset_imm, i64_offset);
  Daddu(temp0, dst_op.rm(), dst_op.offset());
  switch (type.value()) {
    case StoreType::kI64Store8:
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(Lld, Scd, 8, 7);
      break;
    case StoreType::kI32Store8:
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(Ll, Sc, 8, 3);
      break;
    case StoreType::kI64Store16:
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(Lld, Scd, 16, 7);
      break;
    case StoreType::kI32Store16:
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(Ll, Sc, 16, 3);
      break;
    case StoreType::kI64Store32:
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(Lld, Scd, 32, 7);
      break;
    case StoreType::kI32Store:
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER(Ll, Sc);
      break;
    case StoreType::kI64Store:
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER(Lld, Scd);
      break;
    default:
      UNREACHABLE();
  }
}
#undef ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER
#undef ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT

void LiftoffAssembler::AtomicFence() { sync(); }

void LiftoffAssembler::LoadCallerFrameSlot(LiftoffRegister dst,
                                           uint32_t caller_slot_idx,
                                           ValueKind kind) {
  MemOperand src(fp, kSystemPointerSize * (caller_slot_idx + 1));
  liftoff::Load(this, dst, src, kind);
}

void LiftoffAssembler::StoreCallerFrameSlot(LiftoffRegister src,
                                            uint32_t caller_slot_idx,
                                            ValueKind kind,
                                            Register frame_pointer) {
  int32_t offset = kSystemPointerSize * (caller_slot_idx + 1);
  liftoff::Store(this, frame_pointer, offset, src, kind);
}

void LiftoffAssembler::LoadReturnStackSlot(LiftoffRegister dst, int offset,
                                           ValueKind kind) {
  liftoff::Load(this, dst, MemOperand(sp, offset), kind);
}

void LiftoffAssembler::MoveStackValue(uint32_t dst_offset, uint32_t src_offset,
                                      ValueKind kind) {
  DCHECK_NE(dst_offset, src_offset);
  Register scratch = kScratchReg;

  switch (kind) {
    case kI32:
    case kF32:
      Lw(scratch, liftoff::GetStackSlot(src_offset));
      Sw(scratch, liftoff::GetStackSlot(dst_offset));
      break;
    case kI64:
    case kRefNull:
    case kRef:
    case kRtt:
    case kF64:
      Ld(scratch, liftoff::GetStackSlot(src_offset));
      Sd(scratch, liftoff::GetStackSlot(dst_offset));
      break;
    case kS128:
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::Move(Register dst, Register src, ValueKind kind) {
  DCHECK_NE(dst, src);
  // TODO(ksreten): Handle different sizes here.
  MacroAssembler::Move(dst, src);
}

void LiftoffAssembler::Move(DoubleRegister dst, DoubleRegister src,
                            ValueKind kind) {
  DCHECK_NE(dst, src);
  if (kind != kS128) {
    MacroAssembler::Move(dst, src);
  } else {
    MacroAssembler::move_v(dst.toW(), src.toW());
  }
}

void LiftoffAssembler::Spill(int offset, LiftoffRegister reg, ValueKind kind) {
  RecordUsedSpillOffset(offset);
  MemOperand dst = liftoff::GetStackSlot(offset);
  switch (kind) {
    case kI32:
      Sw(reg.gp(), dst);
      break;
    case kI64:
    case kRef:
    case kRefNull:
    case kRtt:
      Sd(reg.gp(), dst);
      break;
    case kF32:
      Swc1(reg.fp(), dst);
      break;
    case kF64:
      MacroAssembler::Sdc1(reg.fp(), dst);
      break;
    case kS128:
      MacroAssembler::st_b(reg.fp().toW(), dst);
      break;
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::Spill(int offset, WasmValue value) {
  RecordUsedSpillOffset(offset);
  MemOperand dst = liftoff::GetStackSlot(offset);
  switch (value.type().kind()) {
    case kI32: {
      MacroAssembler::li(kScratchReg, Operand(value.to_i32()));
      Sw(kScratchReg, dst);
      break;
    }
    case kI64:
    case kRef:
    case kRefNull: {
      MacroAssembler::li(kScratchReg, value.to_i64());
      Sd(kScratchReg, dst);
      break;
    }
    default:
      // kWasmF32 and kWasmF64 are unreachable, since those
      // constants are not tracked.
      UNREACHABLE();
  }
}

void LiftoffAssembler::Fill(LiftoffRegister reg, int offset, ValueKind kind) {
  MemOperand src = liftoff::GetStackSlot(offset);
  switch (kind) {
    case kI32:
      Lw(reg.gp(), src);
      break;
    case kI64:
    case kRef:
    case kRefNull:
      Ld(reg.gp(), src);
      break;
    case kF32:
      Lwc1(reg.fp(), src);
      break;
    case kF64:
      MacroAssembler::Ldc1(reg.fp(), src);
      break;
    case kS128:
      MacroAssembler::ld_b(reg.fp().toW(), src);
      break;
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::FillI64Half(Register, int offset, RegPairHalf) {
  UNREACHABLE();
}

void LiftoffAssembler::FillStackSlotsWithZero(int start, int size) {
  DCHECK_LT(0, size);
  RecordUsedSpillOffset(start + size);

  if (size <= 12 * kStackSlotSize) {
    // Special straight-line code for up to 12 slots. Generates one
    // instruction per slot (<= 12 instructions total).
    uint32_t remainder = size;
    for (; remainder >= kStackSlotSize; remainder -= kStackSlotSize) {
      Sd(zero_reg, liftoff::GetStackSlot(start + remainder));
    }
    DCHECK(remainder == 4 || remainder == 0);
    if (remainder) {
      Sw(zero_reg, liftoff::GetStackSlot(start + remainder));
    }
  } else {
    // General case for bigger counts (12 instructions).
    // Use a0 for start address (inclusive), a1 for end address (exclusive).
    Push(a1, a0);
    Daddu(a0, fp, Operand(-start - size));
    Daddu(a1, fp, Operand(-start));

    Label loop;
    bind(&loop);
    Sd(zero_reg, MemOperand(a0));
    daddiu(a0, a0, kSystemPointerSize);
    BranchShort(&loop, ne, a0, Operand(a1));

    Pop(a1, a0);
  }
}

void LiftoffAssembler::LoadSpillAddress(Register dst, int offset,
                                        ValueKind /* kind */) {
  Dsubu(dst, fp, Operand(offset));
}

void LiftoffAssembler::emit_i64_clz(LiftoffRegister dst, LiftoffRegister src) {
  MacroAssembler::Dclz(dst.gp(), src.gp());
}

void LiftoffAssembler::emit_i64_ctz(LiftoffRegister dst, LiftoffRegister src) {
  MacroAssembler::Dctz(dst.gp(), src.gp());
}

bool LiftoffAssembler::emit_i64_popcnt(LiftoffRegister dst,
                                       LiftoffRegister src) {
  MacroAssembler::Dpopcnt(dst.gp(), src.gp());
  return true;
}

void LiftoffAssembler::IncrementSmi(LiftoffRegister dst, int offset) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  SmiUntag(scratch, MemOperand(dst.gp(), offset));
  Daddu(scratch, scratch, Operand(1));
  SmiTag(scratch);
  Sd(scratch, MemOperand(dst.gp(), offset));
}

void LiftoffAssembler::emit_i32_mul(Register dst, Register lhs, Register rhs) {
  MacroAssembler::Mul(dst, lhs, rhs);
}

void LiftoffAssembler::emit_i32_divs(Register dst, Register lhs, Register rhs,
                                     Label* trap_div_by_zero,
                                     Label* trap_div_unrepresentable) {
  MacroAssembler::Branch(trap_div_by_zero, eq, rhs, Operand(zero_reg));

  // Check if lhs == kMinInt and rhs == -1, since this case is unrepresentable.
  rotr(kScratchReg, lhs, 31);
  sltiu(kScratchReg2, kScratchReg, 2);
  movn(kScratchReg2, kScratchReg, kScratchReg2);
  addu(kScratchReg2, kScratchReg2, rhs);
  MacroAssembler::Branch(trap_div_unrepresentable, eq, kScratchReg2,
                         Operand(zero_reg));

  MacroAssembler::Div(dst, lhs, rhs);
}

void LiftoffAssembler::emit_i32_divu(Register dst, Register lhs, Register rhs,
                                     Label* trap_div_by_zero) {
  MacroAssembler::Branch(trap_div_by_zero, eq, rhs, Operand(zero_reg));
  MacroAssembler::Divu(dst, lhs, rhs);
}

void LiftoffAssembler::emit_i32_rems(Register dst, Register lhs, Register rhs,
                                     Label* trap_div_by_zero) {
  MacroAssembler::Branch(trap_div_by_zero, eq, rhs, Operand(zero_reg));
  MacroAssembler::Mod(dst, lhs, rhs);
}

void LiftoffAssembler::emit_i32_remu(Register dst, Register lhs, Register rhs,
                                     Label* trap_div_by_zero) {
  MacroAssembler::Branch(trap_div_by_zero, eq, rhs, Operand(zero_reg));
  MacroAssembler::Modu(dst, lhs, rhs);
}

#define I32_BINOP(name, instruction)                                 \
  void LiftoffAssembler::emit_i32_##name(Register dst, Register lhs, \
                                         Register rhs) {             \
    instruction(dst, lhs, rhs);                                      \
  }

// clang-format off
I32_BINOP(add, addu)
I32_BINOP(sub, subu)
I32_BINOP(and, and_)
I32_BINOP(or, or_)
I32_BINOP(xor, xor_)
// clang-format on

#undef I32_BINOP

#define I32_BINOP_I(name, instruction)                                  \
  void LiftoffAssembler::emit_i32_##name##i(Register dst, Register lhs, \
                                            int32_t imm) {              \
    instruction(dst, lhs, Operand(imm));                                \
  }

// clang-format off
I32_BINOP_I(add, Addu)
I32_BINOP_I(sub, Subu)
I32_BINOP_I(and, And)
I32_BINOP_I(or, Or)
I32_BINOP_I(xor, Xor)
// clang-format on

#undef I32_BINOP_I

void LiftoffAssembler::emit_i32_clz(Register dst, Register src) {
  MacroAssembler::Clz(dst, src);
}

void LiftoffAssembler::emit_i32_ctz(Register dst, Register src) {
  MacroAssembler::Ctz(dst, src);
}

bool LiftoffAssembler::emit_i32_popcnt(Register dst, Register src) {
  MacroAssembler::Popcnt(dst, src);
  return true;
}

#define I32_SHIFTOP(name, instruction)                               \
  void LiftoffAssembler::emit_i32_##name(Register dst, Register src, \
                                         Register amount) {          \
    instruction(dst, src, amount);                                   \
  }
#define I32_SHIFTOP_I(name, instruction)                                \
  I32_SHIFTOP(name, instruction##v)                                     \
  void LiftoffAssembler::emit_i32_##name##i(Register dst, Register src, \
                                            int amount) {               \
    instruction(dst, src, amount & 31);                                 \
  }

I32_SHIFTOP_I(shl, sll)
I32_SHIFTOP_I(sar, sra)
I32_SHIFTOP_I(shr, srl)

#undef I32_SHIFTOP
#undef I32_SHIFTOP_I

void LiftoffAssembler::emit_i64_addi(LiftoffRegister dst, LiftoffRegister lhs,
                                     int64_t imm) {
  MacroAssembler::Daddu(dst.gp(), lhs.gp(), Operand(imm));
}

void LiftoffAssembler::emit_i64_mul(LiftoffRegister dst, LiftoffRegister lhs,
                                    LiftoffRegister rhs) {
  MacroAssembler::Dmul(dst.gp(), lhs.gp(), rhs.gp());
}

void LiftoffAssembler::emit_i64_muli(LiftoffRegister dst, LiftoffRegister lhs,
                                     int32_t imm) {
  if (base::bits::IsPowerOfTwo(imm)) {
    emit_i64_shli(dst, lhs, base::bits::WhichPowerOfTwo(imm));
    return;
  }
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  MacroAssembler::li(scratch, Operand(imm));
  MacroAssembler::Dmul(dst.gp(), lhs.gp(), scratch);
}

bool LiftoffAssembler::emit_i64_divs(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs,
                                     Label* trap_div_by_zero,
                                     Label* trap_div_unrepresentable) {
  MacroAssembler::Branch(trap_div_by_zero, eq, rhs.gp(), Operand(zero_reg));

  // Check if lhs == MinInt64 and rhs == -1, since this case is unrepresentable.
  drotr32(kScratchReg, lhs.gp(), 31);
  sltiu(kScratchReg2, kScratchReg, 2);
  movn(kScratchReg2, kScratchReg, kScratchReg2);
  daddu(kScratchReg2, kScratchReg2, rhs.gp());
  MacroAssembler::Branch(trap_div_unrepresentable, eq, kScratchReg2,
                         Operand(zero_reg));

  MacroAssembler::Ddiv(dst.gp(), lhs.gp(), rhs.gp());
  return true;
}

bool LiftoffAssembler::emit_i64_divu(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs,
                                     Label* trap_div_by_zero) {
  MacroAssembler::Branch(trap_div_by_zero, eq, rhs.gp(), Operand(zero_reg));
  MacroAssembler::Ddivu(dst.gp(), lhs.gp(), rhs.gp());
  return true;
}

bool LiftoffAssembler::emit_i64_rems(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs,
                                     Label* trap_div_by_zero) {
  MacroAssembler::Branch(trap_div_by_zero, eq, rhs.gp(), Operand(zero_reg));
  MacroAssembler::Dmod(dst.gp(), lhs.gp(), rhs.gp());
  return true;
}

bool LiftoffAssembler::emit_i64_remu(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs,
                                     Label* trap_div_by_zero) {
  MacroAssembler::Branch(trap_div_by_zero, eq, rhs.gp(), Operand(zero_reg));
  MacroAssembler::Dmodu(dst.gp(), lhs.gp(), rhs.gp());
  return true;
}

#define I64_BINOP(name, instruction)                                   \
  void LiftoffAssembler::emit_i64_##name(                              \
      LiftoffRegister dst, LiftoffRegister lhs, LiftoffRegister rhs) { \
    instruction(dst.gp(), lhs.gp(), rhs.gp());                         \
  }

// clang-format off
I64_BINOP(add, daddu)
I64_BINOP(sub, dsubu)
I64_BINOP(and, and_)
I64_BINOP(or, or_)
I64_BINOP(xor, xor_)
// clang-format on

#undef I64_BINOP

#define I64_BINOP_I(name, instruction)                         \
  void LiftoffAssembler::emit_i64_##name##i(                   \
      LiftoffRegister dst, LiftoffRegister lhs, int32_t imm) { \
    instruction(dst.gp(), lhs.gp(), Operand(imm));             \
  }

// clang-format off
I64_BINOP_I(and, And)
I64_BINOP_I(or, Or)
I64_BINOP_I(xor, Xor)
// clang-format on

#undef I64_BINOP_I

#define I64_SHIFTOP(name, instruction)                             \
  void LiftoffAssembler::emit_i64_##name(                          \
      LiftoffRegister dst, LiftoffRegister src, Register amount) { \
    instruction(dst.gp(), src.gp(), amount);                       \
  }
#define I64_SHIFTOP_I(name, instruction)                                       \
  I64_SHIFTOP(name, instruction##v)                                            \
  void LiftoffAssembler::emit_i64_##name##i(LiftoffRegister dst,               \
                                            LiftoffRegister src, int amount) { \
    amount &= 63;                                                              \
    if (amount < 32)                                                           \
      instruction(dst.gp(), src.gp(), amount);                                 \
    else                                                                       \
      instruction##32(dst.gp(), src.gp(), amount - 32);                        \
  }

I64_SHIFTOP_I(shl, dsll)
I64_SHIFTOP_I(sar, dsra)
I64_SHIFTOP_I(shr, dsrl)

#undef I64_SHIFTOP
#undef I64_SHIFTOP_I

void LiftoffAssembler::emit_u32_to_uintptr(Register dst, Register src) {
  Dext(dst, src, 0, 32);
}

void LiftoffAssembler::clear_i32_upper_half(Register dst) {
  // Don't need to clear the upper halves of i32 values for sandbox on MIPS64,
  // because we'll explicitly zero-extend their lower halves before using them
  // for memory accesses anyway.
}

void LiftoffAssembler::emit_f32_neg(DoubleRegister dst, DoubleRegister src) {
  MacroAssembler::Neg_s(dst, src);
}

void LiftoffAssembler::emit_f64_neg(DoubleRegister dst, DoubleRegister src) {
  MacroAssembler::Neg_d(dst, src);
}

void LiftoffAssembler::emit_f32_min(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  Label ool, done;
  MacroAssembler::Float32Min(dst, lhs, rhs, &ool);
  Branch(&done);

  bind(&ool);
  MacroAssembler::Float32MinOutOfLine(dst, lhs, rhs);
  bind(&done);
}

void LiftoffAssembler::emit_f32_max(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  Label ool, done;
  MacroAssembler::Float32Max(dst, lhs, rhs, &ool);
  Branch(&done);

  bind(&ool);
  MacroAssembler::Float32MaxOutOfLine(dst, lhs, rhs);
  bind(&done);
}

void LiftoffAssembler::emit_f32_copysign(DoubleRegister dst, DoubleRegister lhs,
                                         DoubleRegister rhs) {
  if (CpuFeatures::IsSupported(MIPS_SIMD)) {
    DoubleRegister scratch = rhs;
    if (dst == rhs) {
      scratch = kScratchDoubleReg;
      Move_d(scratch, rhs);
    }
    if (dst != lhs) {
      Move_d(dst, lhs);
    }
    binsli_w(dst.toW(), scratch.toW(), 0);
  } else {
    UseScratchRegisterScope temps(this);
    Register scratch1 = temps.Acquire();
    Register scratch2 = temps.Acquire();
    mfc1(scratch1, lhs);
    mfc1(scratch2, rhs);
    srl(scratch2, scratch2, 31);
    Ins(scratch1, scratch2, 31, 1);
    mtc1(scratch1, dst);
  }
}

void LiftoffAssembler::emit_f64_min(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  Label ool, done;
  MacroAssembler::Float64Min(dst, lhs, rhs, &ool);
  Branch(&done);

  bind(&ool);
  MacroAssembler::Float64MinOutOfLine(dst, lhs, rhs);
  bind(&done);
}

void LiftoffAssembler::emit_f64_max(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  Label ool, done;
  MacroAssembler::Float64Max(dst, lhs, rhs, &ool);
  Branch(&done);

  bind(&ool);
  MacroAssembler::Float64MaxOutOfLine(dst, lhs, rhs);
  bind(&done);
}

void LiftoffAssembler::emit_f64_copysign(DoubleRegister dst, DoubleRegister lhs,
                                         DoubleRegister rhs) {
  if (CpuFeatures::IsSupported(MIPS_SIMD)) {
    DoubleRegister scratch = rhs;
    if (dst == rhs) {
      scratch = kScratchDoubleReg;
      Move_d(scratch, rhs);
    }
    if (dst != lhs) {
      Move_d(dst, lhs);
    }
    binsli_d(dst.toW(), scratch.toW(), 0);
  } else {
    UseScratchRegisterScope temps(this);
    Register scratch1 = temps.Acquire();
    Register scratch2 = temps.Acquire();
    dmfc1(scratch1, lhs);
    dmfc1(scratch2, rhs);
    dsrl32(scratch2, scratch2, 31);
    Dins(scratch1, scratch2, 63, 1);
    dmtc1(scratch1, dst);
  }
}

#define FP_BINOP(name, instruction)                                          \
  void LiftoffAssembler::emit_##name(DoubleRegister dst, DoubleRegister lhs, \
                                     DoubleRegister rhs) {                   \
    instruction(dst, lhs, rhs);                                              \
  }
#define FP_UNOP(name, instruction)                                             \
  void LiftoffAssembler::emit_##name(DoubleRegister dst, DoubleRegister src) { \
    instruction(dst, src);                                                     \
  }
#define FP_UNOP_RETURN_TRUE(name, instruction)                                 \
  bool LiftoffAssembler::emit_##name(DoubleRegister dst, DoubleRegister src) { \
    instruction(dst, src);                                                     \
    return true;                                                               \
  }

FP_BINOP(f32_add, add_s)
FP_BINOP(f32_sub, sub_s)
FP_BINOP(f32_mul, mul_s)
FP_BINOP(f32_div, div_s)
FP_UNOP(f32_abs, abs_s)
FP_UNOP_RETURN_TRUE(f32_ceil, Ceil_s_s)
FP_UNOP_RETURN_TRUE(f32_floor, Floor_s_s)
FP_UNOP_RETURN_TRUE(f32_trunc, Trunc_s_s)
FP_UNOP_RETURN_TRUE(f32_nearest_int, Round_s_s)
FP_UNOP(f32_sqrt, sqrt_s)
FP_BINOP(f64_add, add_d)
FP_BINOP(f64_sub, sub_d)
FP_BINOP(f64_mul, mul_d)
FP_BINOP(f64_div, div_d)
FP_UNOP(f64_abs, abs_d)
FP_UNOP_RETURN_TRUE(f64_ceil, Ceil_d_d)
FP_UNOP_RETURN_TRUE(f64_floor, Floor_d_d)
FP_UNOP_RETURN_TRUE(f64_trunc, Trunc_d_d)
FP_UNOP_RETURN_TRUE(f64_nearest_int, Round_d_d)
FP_UNOP(f64_sqrt, sqrt_d)

#undef FP_BINOP
#undef FP_UNOP
#undef FP_UNOP_RETURN_TRUE

bool LiftoffAssembler::emit_type_conversion(WasmOpcode opcode,
                                            LiftoffRegister dst,
                                            LiftoffRegister src, Label* trap) {
  switch (opcode) {
    case kExprI32ConvertI64:
      MacroAssembler::Ext(dst.gp(), src.gp(), 0, 32);
      return true;
    case kExprI32SConvertF32: {
      LiftoffRegister rounded = GetUnusedRegister(kFpReg, LiftoffRegList{src});
      LiftoffRegister converted_back =
          GetUnusedRegister(kFpReg, LiftoffRegList{src, rounded});

      // Real conversion.
      MacroAssembler::Trunc_s_s(rounded.fp(), src.fp());
      trunc_w_s(kScratchDoubleReg, rounded.fp());
      mfc1(dst.gp(), kScratchDoubleReg);
      // Avoid INT32_MAX as an overflow indicator and use INT32_MIN instead,
      // because INT32_MIN allows easier out-of-bounds detection.
      MacroAssembler::Addu(kScratchReg, dst.gp(), 1);
      MacroAssembler::Slt(kScratchReg2, kScratchReg, dst.gp());
      MacroAssembler::Movn(dst.gp(), kScratchReg, kScratchReg2);

      // Checking if trap.
      mtc1(dst.gp(), kScratchDoubleReg);
      cvt_s_w(converted_back.fp(), kScratchDoubleReg);
      MacroAssembler::CompareF32(EQ, rounded.fp(), converted_back.fp());
      MacroAssembler::BranchFalseF(trap);
      return true;
    }
    case kExprI32UConvertF32: {
      LiftoffRegister rounded = GetUnusedRegister(kFpReg, LiftoffRegList{src});
      LiftoffRegister converted_back =
          GetUnusedRegister(kFpReg, LiftoffRegList{src, rounded});

      // Real conversion.
      MacroAssembler::Trunc_s_s(rounded.fp(), src.fp());
      MacroAssembler::Trunc_uw_s(dst.gp(), rounded.fp(), kScratchDoubleReg);
      // Avoid UINT32_MAX as an overflow indicator and use 0 instead,
      // because 0 allows easier out-of-bounds detection.
      MacroAssembler::Addu(kScratchReg, dst.gp(), 1);
      MacroAssembler::Movz(dst.gp(), zero_reg, kScratchReg);

      // Checking if trap.
      MacroAssembler::Cvt_d_uw(converted_back.fp(), dst.gp());
      cvt_s_d(converted_back.fp(), converted_back.fp());
      MacroAssembler::CompareF32(EQ, rounded.fp(), converted_back.fp());
      MacroAssembler::BranchFalseF(trap);
      return true;
    }
    case kExprI32SConvertF64: {
      LiftoffRegister rounded = GetUnusedRegister(kFpReg, LiftoffRegList{src});
      LiftoffRegister converted_back =
          GetUnusedRegister(kFpReg, LiftoffRegList{src, rounded});

      // Real conversion.
      MacroAssembler::Trunc_d_d(rounded.fp(), src.fp());
      trunc_w_d(kScratchDoubleReg, rounded.fp());
      mfc1(dst.gp(), kScratchDoubleReg);

      // Checking if trap.
      cvt_d_w(converted_back.fp(), kScratchDoubleReg);
      MacroAssembler::CompareF64(EQ, rounded.fp(), converted_back.fp());
      MacroAssembler::BranchFalseF(trap);
      return true;
    }
    case kExprI32UConvertF64: {
      LiftoffRegister rounded = GetUnusedRegister(kFpReg, LiftoffRegList{src});
      LiftoffRegister converted_back =
          GetUnusedRegister(kFpReg, LiftoffRegList{src, rounded});

      // Real conversion.
      MacroAssembler::Trunc_d_d(rounded.fp(), src.fp());
      MacroAssembler::Trunc_uw_d(dst.gp(), rounded.fp(), kScratchDoubleReg);

      // Checking if trap.
      MacroAssembler::Cvt_d_uw(converted_back.fp(), dst.gp());
      MacroAssembler::CompareF64(EQ, rounded.fp(), converted_back.fp());
      MacroAssembler::BranchFalseF(trap);
      return true;
    }
    case kExprI32ReinterpretF32:
      MacroAssembler::FmoveLow(dst.gp(), src.fp());
      return true;
    case kExprI64SConvertI32:
      sll(dst.gp(), src.gp(), 0);
      return true;
    case kExprI64UConvertI32:
      MacroAssembler::Dext(dst.gp(), src.gp(), 0, 32);
      return true;
    case kExprI64SConvertF32: {
      LiftoffRegister rounded = GetUnusedRegister(kFpReg, LiftoffRegList{src});
      LiftoffRegister converted_back =
          GetUnusedRegister(kFpReg, LiftoffRegList{src, rounded});

      // Real conversion.
      MacroAssembler::Trunc_s_s(rounded.fp(), src.fp());
      trunc_l_s(kScratchDoubleReg, rounded.fp());
      dmfc1(dst.gp(), kScratchDoubleReg);
      // Avoid INT64_MAX as an overflow indicator and use INT64_MIN instead,
      // because INT64_MIN allows easier out-of-bounds detection.
      MacroAssembler::Daddu(kScratchReg, dst.gp(), 1);
      MacroAssembler::Slt(kScratchReg2, kScratchReg, dst.gp());
      MacroAssembler::Movn(dst.gp(), kScratchReg, kScratchReg2);

      // Checking if trap.
      dmtc1(dst.gp(), kScratchDoubleReg);
      cvt_s_l(converted_back.fp(), kScratchDoubleReg);
      MacroAssembler::CompareF32(EQ, rounded.fp(), converted_back.fp());
      MacroAssembler::BranchFalseF(trap);
      return true;
    }
    case kExprI64UConvertF32: {
      // Real conversion.
      MacroAssembler::Trunc_ul_s(dst.gp(), src.fp(), kScratchDoubleReg,
                                 kScratchReg);

      // Checking if trap.
      MacroAssembler::Branch(trap, eq, kScratchReg, Operand(zero_reg));
      return true;
    }
    case kExprI64SConvertF64: {
      LiftoffRegister rounded = GetUnusedRegister(kFpReg, LiftoffRegList{src});
      LiftoffRegister converted_back =
          GetUnusedRegister(kFpReg, LiftoffRegList{src, rounded});

      // Real conversion.
      MacroAssembler::Trunc_d_d(rounded.fp(), src.fp());
      trunc_l_d(kScratchDoubleReg, rounded.fp());
      dmfc1(dst.gp(), kScratchDoubleReg);
      // Avoid INT64_MAX as an overflow indicator and use INT64_MIN instead,
      // because INT64_MIN allows easier out-of-bounds detection.
      MacroAssembler::Daddu(kScratchReg, dst.gp(), 1);
      MacroAssembler::Slt(kScratchReg2, kScratchReg, dst.gp());
      MacroAssembler::Movn(dst.gp(), kScratchReg, kScratchReg2);

      // Checking if trap.
      dmtc1(dst.gp(), kScratchDoubleReg);
      cvt_d_l(converted_back.fp(), kScratchDoubleReg);
      MacroAssembler::CompareF64(EQ, rounded.fp(), converted_back.fp());
      MacroAssembler::BranchFalseF(trap);
      return true;
    }
    case kExprI64UConvertF64: {
      // Real conversion.
      MacroAssembler::Trunc_ul_d(dst.gp(), src.fp(), kScratchDoubleReg,
                                 kScratchReg);

      // Checking if trap.
      MacroAssembler::Branch(trap, eq, kScratchReg, Operand(zero_reg));
      return true;
    }
    case kExprI64ReinterpretF64:
      dmfc1(dst.gp(), src.fp());
      return true;
    case kExprF32SConvertI32: {
      LiftoffRegister scratch = GetUnusedRegister(kFpReg, LiftoffRegList{dst});
      mtc1(src.gp(), scratch.fp());
      cvt_s_w(dst.fp(), scratch.fp());
      return true;
    }
    case kExprF32UConvertI32:
      MacroAssembler::Cvt_s_uw(dst.fp(), src.gp());
      return true;
    case kExprF32ConvertF64:
      cvt_s_d(dst.fp(), src.fp());
      return true;
    case kExprF32ReinterpretI32:
      MacroAssembler::FmoveLow(dst.fp(), src.gp());
      return true;
    case kExprF64SConvertI32: {
      LiftoffRegister scratch = GetUnusedRegister(kFpReg, LiftoffRegList{dst});
      mtc1(src.gp(), scratch.fp());
      cvt_d_w(dst.fp(), scratch.fp());
      return true;
    }
    case kExprF64UConvertI32:
      MacroAssembler::Cvt_d_uw(dst.fp(), src.gp());
      return true;
    case kExprF64ConvertF32:
      cvt_d_s(dst.fp(), src.fp());
      return true;
    case kExprF64ReinterpretI64:
      dmtc1(src.gp(), dst.fp());
      return true;
    case kExprI32SConvertSatF32: {
      // Other arches use round to zero here, so we follow.
      if (CpuFeatures::IsSupported(MIPS_SIMD)) {
        trunc_w_s(kScratchDoubleReg, src.fp());
        mfc1(dst.gp(), kScratchDoubleReg);
      } else {
        Label done;
        mov(dst.gp(), zero_reg);
        CompareIsNanF32(src.fp(), src.fp());
        BranchTrueShortF(&done);
        li(dst.gp(), static_cast<int32_t>(std::numeric_limits<int32_t>::min()));
        MacroAssembler::Move(
            kScratchDoubleReg,
            static_cast<float>(std::numeric_limits<int32_t>::min()));
        CompareF32(OLT, src.fp(), kScratchDoubleReg);
        BranchTr
"""


```