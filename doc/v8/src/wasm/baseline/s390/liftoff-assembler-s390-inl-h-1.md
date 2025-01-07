Response:
The user wants me to analyze a C++ header file from the V8 JavaScript engine.
Specifically, they want me to:
1. **List the functionalities** of the provided code snippet.
2. **Check if it's a Torque file:** Based on the filename ending (`.tq`).
3. **Explain its relation to JavaScript** and provide a JavaScript example if applicable.
4. **Illustrate code logic with input and output examples.**
5. **Highlight common programming errors** related to the code.
6. **Summarize the functionalities** in this specific part of the file (part 2 of 4).

Let's break down the code to understand its functionality. The code defines methods within the `LiftoffAssembler` class, specifically for the s390 architecture. These methods seem to implement low-level operations related to:
- **Atomic memory operations:** Compare and exchange, exchange.
- **Stack frame manipulation:** Loading and storing values from caller and current frames.
- **Memory manipulation:** Moving data on the stack.
- **Register movement:** Moving data between registers.
- **Stack spilling and filling:** Saving and restoring register values to the stack.
- **Bitwise operations:** Popcount, sign extension, count leading/trailing zeros.
- **Floating-point operations:** Ceil, floor, trunc, nearest int, abs, neg, sqrt, min, max, add, sub, mul, div, copysign.
- **Integer arithmetic and logical operations:** Add, subtract, multiply, divide, remainder, shift, and, or, xor.
- **Type conversions:** Converting between integer and floating-point types.

The filename `liftoff-assembler-s390-inl.h` suggests that this is an inline header file for the Liftoff compiler's assembler, specific to the s390 architecture. Liftoff is a baseline compiler for WebAssembly in V8.

Based on the file extension, it's not a Torque file.

The code is directly related to how JavaScript (specifically WebAssembly) is executed on the s390 architecture. The functions here are used to generate machine code for various WebAssembly operations.

Let's think about an example for `AtomicCompareExchange`. Suppose we have a shared memory location, and two threads try to update it.

Common programming errors related to atomic operations include race conditions if not used correctly, and incorrect memory ordering if fences are not used appropriately. For stack manipulation, errors could involve incorrect offsets leading to reading or writing to the wrong memory locations. For type conversions, not handling potential traps (overflows, invalid conversions) is a common error.

Finally, I need to summarize the functionalities of this specific part, which primarily focuses on atomic operations, stack/memory manipulation, basic arithmetic/logical operations, and type conversions.
这是 `v8/src/wasm/baseline/s390/liftoff-assembler-s390-inl.h` 文件的第二部分代码，它定义了 `LiftoffAssembler` 类的一些内联方法，用于为 WebAssembly 的 Liftoff 编译器在 s390 架构上生成机器代码。

**功能列表:**

1. **原子操作 (Atomic Operations):**
   - `AtomicCompareExchange`: 实现原子比较并交换操作，用于在多线程环境下安全地更新内存。支持 8 位、16 位、32 位和 64 位的值。
   - `AtomicExchange`: 实现原子交换操作，将内存中的值与给定的值进行原子替换。支持 8 位、16 位、32 位和 64 位的值。
   - `AtomicFence`:  插入一个原子栅栏，用于确保内存操作的顺序性（目前实现为 bailout，即回退到更慢但更安全的执行路径）。

2. **栈帧操作 (Stack Frame Operations):**
   - `LoadCallerFrameSlot`: 从调用者的栈帧中加载指定槽位的值。支持加载 i32, i64, f32, f64 和 s128 类型的值。
   - `StoreCallerFrameSlot`: 将值存储到调用者的栈帧的指定槽位。支持存储 i32, i64, f32, f64 和 s128 类型的值。
   - `LoadReturnStackSlot`: 从返回栈中加载指定偏移量的值。支持加载 i32, i64, f32, f64 和 s128 类型的值。

3. **内存操作 (Memory Operations):**
   - `MoveStackValue`: 在栈上移动指定大小的值。

4. **寄存器操作 (Register Operations):**
   - `Move`: 在通用寄存器或浮点寄存器之间移动值。

5. **栈溢出和填充 (Stack Spilling and Filling):**
   - `Spill`: 将寄存器的值保存到栈上的指定偏移量。
   - `Fill`: 将栈上指定偏移量的值加载到寄存器。
   - `FillI64Half`:  对于 i64 类型，填充一半寄存器（此部分代码中为 `UNREACHABLE()`，表示当前未实现或不适用）。
   - `FillStackSlotsWithZero`: 将栈上的指定范围填充为零。
   - `LoadSpillAddress`: 加载栈上溢出位置的地址到寄存器。

6. **一元操作 (Unary Operations):**
   - 提供一系列 `emit_` 开头的方法，用于执行各种一元操作，包括：
     - **整数操作:** `i32_popcnt`, `i64_popcnt`, `i32_signextend_i8`, `i32_signextend_i16`, `i64_signextend_i8`, `i64_signextend_i16`, `i64_signextend_i32`, `i32_clz`, `i32_ctz`, `i64_clz`, `i64_ctz`.
     - **浮点数操作:** `f32_ceil`, `f32_floor`, `f32_trunc`, `f32_nearest_int`, `f32_abs`, `f32_neg`, `f32_sqrt`, `f64_ceil`, `f64_floor`, `f64_trunc`, `f64_nearest_int`, `f64_abs`, `f64_neg`, `f64_sqrt`.
     - `u32_to_uintptr`: 将无符号 32 位整数加载到通用寄存器。

7. **二元操作 (Binary Operations):**
   - 提供一系列 `emit_` 开头的方法，用于执行各种二元操作，包括：
     - **浮点数操作:** `f32_min`, `f32_max`, `f64_min`, `f64_max`, `f64_add`, `f64_sub`, `f64_mul`, `f64_div`, `f32_add`, `f32_sub`, `f32_mul`, `f32_div`.
     - **整数移位操作:** `i32_shli`, `i32_sari`, `i32_shri`, `i32_shl`, `i32_sar`, `i32_shr`, `i64_shl`, `i64_sar`, `i64_shr`, `i64_shli`, `i64_sari`, `i64_shri`.
     - **整数算术和逻辑操作:** `i32_addi`, `i32_subi`, `i32_andi`, `i32_ori`, `i32_xori`, `i32_add`, `i32_sub`, `i32_and`, `i32_or`, `i32_xor`, `i32_mul`, `i64_add`, `i64_sub`, `i64_mul`, `i64_and`, `i64_or`, `i64_xor`, `i64_addi`, `i64_andi`, `i64_ori`, `i64_xori`.

8. **Smi 操作 (Small Integer Operations):**
   - `IncrementSmi`: 递增一个 Smi（V8 中用于表示小整数的特殊类型）。

9. **除法和求余操作 (Division and Remainder Operations):**
   - 提供 `emit_i32_divs`, `emit_i32_divu`, `emit_i32_rems`, `emit_i32_remu`, `emit_i64_divs`, `emit_i64_divu`, `emit_i64_rems`, `emit_i64_remu` 等方法，用于处理有符号和无符号整数的除法和求余操作，并处理除零错误。

10. **浮点数符号复制 (Floating-point Copy Sign):**
    - `emit_f32_copysign`, `emit_f64_copysign`: 将一个浮点数的符号复制到另一个浮点数。

11. **类型转换 (Type Conversion):**
    - `emit_type_conversion`:  处理各种类型转换操作，例如整数和浮点数之间的转换，并处理可能发生的陷阱（trap）。

**关于文件类型:**

`v8/src/wasm/baseline/s390/liftoff-assembler-s390-inl.h` 以 `.h` 结尾，这是一个标准的 C++ 头文件。因此，它**不是**以 `.tq` 结尾的 V8 Torque 源代码。

**与 JavaScript 的关系:**

这段代码是 V8 JavaScript 引擎的一部分，专门用于 WebAssembly 的即时编译（JIT）在 s390 架构上的实现。当 JavaScript 代码中调用 WebAssembly 模块时，V8 的 Liftoff 编译器会使用这些方法来生成底层的机器指令，从而执行 WebAssembly 代码。

**JavaScript 示例 (与原子操作相关):**

虽然这些 C++ 代码直接服务于 WebAssembly，但 WebAssembly 的原子操作可以被 JavaScript 调用。例如：

```javascript
const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 1);
const ia = new Int32Array(sab);

Atomics.store(ia, 0, 10); // 初始值

// 模拟并发修改
function workerFunc() {
  const expected = 10;
  const replacement = 20;
  const result = Atomics.compareExchange(ia, 0, expected, replacement);
  console.log(`Worker: compareExchange result: ${result}, current value: ${Atomics.load(ia, 0)}`);
}

const worker = new Worker(URL.createObjectURL(new Blob([`(${workerFunc})()`])));
workerFunc(); // 主线程也尝试修改

```

在这个例子中，`Atomics.compareExchange` 操作在底层会触发类似 `LiftoffAssembler::AtomicCompareExchange` 这样的 C++ 代码的执行，以确保操作的原子性。

**代码逻辑推理与假设输入输出 (以 `AtomicCompareExchange` 为例):**

**假设输入:**

- `dst_addr`: 目标内存地址的寄存器，假设为寄存器 `r2`，指向地址 `0x1000`。
- `offset_imm`: 内存偏移量，假设为 `0`。
- `expected`: 期望的旧值寄存器，假设为寄存器 `r3`，值为 `10`。
- `new_value`: 新值的寄存器，假设为寄存器 `r4`，值为 `20`。
- `result`: 存储结果的寄存器，假设为寄存器 `r5`。
- `type`:  `StoreType::kI32Store` (32 位存储)。

**代码逻辑:**

1. 将目标地址 `r2` 加上偏移量 `0` 得到最终操作地址。
2. 在一个循环中：
   - 从目标地址原子地加载当前值到临时寄存器 `tmp1`。
   - 将 `expected` 的值与 `tmp1` 进行比较。
   - 如果相等，则将 `new_value` 存储到目标地址，并将 `expected` 的旧值存储到 `result` 寄存器。操作成功，跳出循环。
   - 如果不相等，则将目标地址的当前值（即 `tmp1` 的值）存储到 `result` 寄存器，并继续循环，重试操作。

**假设输出:**

如果内存地址 `0x1000` 的当前值是 `10`：

- `result` 寄存器 `r5` 的值将是 `10` (旧值)。
- 内存地址 `0x1000` 的值将被更新为 `20`。

如果内存地址 `0x1000` 的当前值不是 `10`，例如是 `15`：

- `result` 寄存器 `r5` 的值将是 `15` (当前值)。
- 内存地址 `0x1000` 的值保持不变。
- 代码会循环重试，直到内存中的值变为 `10`，或者外部因素导致不再满足交换条件。

**用户常见的编程错误 (与原子操作和栈操作相关):**

1. **未正确处理原子操作的返回值:** 例如，`AtomicCompareExchange` 返回旧值，程序员可能没有检查返回值来判断操作是否成功，导致逻辑错误。
2. **不正确的内存对齐:** 虽然这段代码处理了不同大小的数据，但在其他涉及内存操作的代码中，未正确对齐的内存访问可能导致崩溃或性能问题。
3. **栈溢出:** 在进行栈帧操作时，如果计算的偏移量不正确，可能会读写到栈帧之外的内存，导致程序崩溃。
4. **竞态条件 (Race Conditions):**  即使使用了原子操作，如果程序的整体逻辑没有正确地设计并发控制，仍然可能存在竞态条件。例如，多个原子操作之间的状态依赖没有被正确处理。
5. **错误的类型转换:** 在使用 `emit_type_conversion` 等方法时，如果没有正确处理转换可能导致的溢出或精度损失，可能会产生意想不到的结果。例如，将一个超出 `int32` 范围的浮点数转换为 `i32`。

**归纳功能 (第 2 部分):**

这段代码主要负责实现 WebAssembly 在 s390 架构上的**原子内存操作**、**栈帧的管理和数据的存取**、**基本的内存操作**、**寄存器数据的移动**、**栈数据的溢出和填充**，以及大量的**一元和二元运算操作 (包括整数和浮点数运算)** 和**类型转换**。这些功能是 Liftoff 编译器生成正确且高效的机器代码的关键组成部分。

Prompt: 
```
这是目录为v8/src/wasm/baseline/s390/liftoff-assembler-s390-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/s390/liftoff-assembler-s390-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
gister tmp1 = GetUnusedRegister(kGpReg, pinned).gp();
  pinned.set(tmp1);
  Register tmp2 = GetUnusedRegister(kGpReg, pinned).gp();

  PREP_MEM_OPERAND(offset_reg, offset_imm, ip)
  lay(ip,
      MemOperand(dst_addr, offset_reg == no_reg ? r0 : offset_reg, offset_imm));

  switch (type.value()) {
    case StoreType::kI32Store8:
    case StoreType::kI64Store8: {
      Label do_again;
      bind(&do_again);
      LoadU8(tmp1, MemOperand(ip));
      XorP(tmp2, tmp1, value.gp());
      AtomicCmpExchangeU8(ip, result.gp(), tmp1, tmp2, r0, r1);
      b(Condition(4), &do_again);
      LoadU8(result.gp(), result.gp());
      break;
    }
    case StoreType::kI32Store16:
    case StoreType::kI64Store16: {
      Label do_again;
      bind(&do_again);
      LoadU16(tmp1, MemOperand(ip));
#ifdef V8_TARGET_BIG_ENDIAN
      lrvr(tmp2, tmp1);
      ShiftRightU32(tmp2, tmp2, Operand(16));
      XorP(tmp2, tmp2, value.gp());
      lrvr(tmp2, tmp2);
      ShiftRightU32(tmp2, tmp2, Operand(16));
#else
      XorP(tmp2, tmp1, value.gp());
#endif
      AtomicCmpExchangeU16(ip, result.gp(), tmp1, tmp2, r0, r1);
      b(Condition(4), &do_again);
      LoadU16(result.gp(), result.gp());
#ifdef V8_TARGET_BIG_ENDIAN
      lrvr(result.gp(), result.gp());
      ShiftRightU32(result.gp(), result.gp(), Operand(16));
#endif
      break;
    }
    case StoreType::kI32Store:
    case StoreType::kI64Store32: {
      Label do_again;
      bind(&do_again);
      LoadU32(tmp1, MemOperand(ip));
#ifdef V8_TARGET_BIG_ENDIAN
      lrvr(tmp2, tmp1);
      XorP(tmp2, tmp2, value.gp());
      lrvr(tmp2, tmp2);
#else
      XorP(tmp2, tmp1, value.gp());
#endif
      CmpAndSwap(tmp1, tmp2, MemOperand(ip));
      b(Condition(4), &do_again);
      LoadU32(result.gp(), tmp1);
#ifdef V8_TARGET_BIG_ENDIAN
      lrvr(result.gp(), result.gp());
#endif
      break;
    }
    case StoreType::kI64Store: {
      Label do_again;
      bind(&do_again);
      LoadU64(tmp1, MemOperand(ip));
#ifdef V8_TARGET_BIG_ENDIAN
      lrvgr(tmp2, tmp1);
      XorP(tmp2, tmp2, value.gp());
      lrvgr(tmp2, tmp2);
#else
      XorP(tmp2, tmp1, value.gp());
#endif
      CmpAndSwap64(tmp1, tmp2, MemOperand(ip));
      b(Condition(4), &do_again);
      mov(result.gp(), tmp1);
#ifdef V8_TARGET_BIG_ENDIAN
      lrvgr(result.gp(), result.gp());
#endif
      break;
    }
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::AtomicExchange(Register dst_addr, Register offset_reg,
                                      uintptr_t offset_imm,
                                      LiftoffRegister value,
                                      LiftoffRegister result, StoreType type,
                                      bool i64_offset) {
  PREP_MEM_OPERAND(offset_reg, offset_imm, ip)
  lay(ip,
      MemOperand(dst_addr, offset_reg == no_reg ? r0 : offset_reg, offset_imm));

  switch (type.value()) {
    case StoreType::kI32Store8:
    case StoreType::kI64Store8: {
      AtomicExchangeU8(ip, value.gp(), result.gp(), r0);
      LoadU8(result.gp(), result.gp());
      break;
    }
    case StoreType::kI32Store16:
    case StoreType::kI64Store16: {
#ifdef V8_TARGET_BIG_ENDIAN
      lrvr(r1, value.gp());
      ShiftRightU32(r1, r1, Operand(16));
#else
      LoadU16(r1, value.gp());
#endif
      AtomicExchangeU16(ip, r1, result.gp(), r0);
#ifdef V8_TARGET_BIG_ENDIAN
      lrvr(result.gp(), result.gp());
      ShiftRightU32(result.gp(), result.gp(), Operand(16));
#else
      LoadU16(result.gp(), result.gp());
#endif
      break;
    }
    case StoreType::kI32Store:
    case StoreType::kI64Store32: {
#ifdef V8_TARGET_BIG_ENDIAN
      lrvr(r1, value.gp());
#else
      LoadU32(r1, value.gp());
#endif
      Label do_cs;
      bind(&do_cs);
      cs(result.gp(), r1, MemOperand(ip));
      bne(&do_cs, Label::kNear);
#ifdef V8_TARGET_BIG_ENDIAN
      lrvr(result.gp(), result.gp());
#endif
      LoadU32(result.gp(), result.gp());
      break;
    }
    case StoreType::kI64Store: {
#ifdef V8_TARGET_BIG_ENDIAN
      lrvgr(r1, value.gp());
#else
      mov(r1, value.gp());
#endif
      Label do_cs;
      bind(&do_cs);
      csg(result.gp(), r1, MemOperand(ip));
      bne(&do_cs, Label::kNear);
#ifdef V8_TARGET_BIG_ENDIAN
      lrvgr(result.gp(), result.gp());
#endif
      break;
    }
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::AtomicCompareExchange(
    Register dst_addr, Register offset_reg, uintptr_t offset_imm,
    LiftoffRegister expected, LiftoffRegister new_value, LiftoffRegister result,
    StoreType type, bool i64_offset) {

  LiftoffRegList pinned = LiftoffRegList{dst_addr, expected, new_value, result};
  if (offset_reg != no_reg) pinned.set(offset_reg);
  Register tmp1 = GetUnusedRegister(kGpReg, pinned).gp();
  pinned.set(tmp1);
  Register tmp2 = GetUnusedRegister(kGpReg, pinned).gp();

  PREP_MEM_OPERAND(offset_reg, offset_imm, ip)
  lay(ip,
      MemOperand(dst_addr, offset_reg == no_reg ? r0 : offset_reg, offset_imm));

  switch (type.value()) {
    case StoreType::kI32Store8:
    case StoreType::kI64Store8: {
      AtomicCmpExchangeU8(ip, result.gp(), expected.gp(), new_value.gp(), r0,
                          r1);
      LoadU8(result.gp(), result.gp());
      break;
    }
    case StoreType::kI32Store16:
    case StoreType::kI64Store16: {
#ifdef V8_TARGET_BIG_ENDIAN
      lrvr(tmp1, expected.gp());
      lrvr(tmp2, new_value.gp());
      ShiftRightU32(tmp1, tmp1, Operand(16));
      ShiftRightU32(tmp2, tmp2, Operand(16));
#else
      LoadU16(tmp1, expected.gp());
      LoadU16(tmp2, new_value.gp());
#endif
      AtomicCmpExchangeU16(ip, result.gp(), tmp1, tmp2, r0, r1);
      LoadU16(result.gp(), result.gp());
#ifdef V8_TARGET_BIG_ENDIAN
      lrvr(result.gp(), result.gp());
      ShiftRightU32(result.gp(), result.gp(), Operand(16));
#endif
      break;
    }
    case StoreType::kI32Store:
    case StoreType::kI64Store32: {
#ifdef V8_TARGET_BIG_ENDIAN
      lrvr(tmp1, expected.gp());
      lrvr(tmp2, new_value.gp());
#else
      LoadU32(tmp1, expected.gp());
      LoadU32(tmp2, new_value.gp());
#endif
      CmpAndSwap(tmp1, tmp2, MemOperand(ip));
      LoadU32(result.gp(), tmp1);
#ifdef V8_TARGET_BIG_ENDIAN
      lrvr(result.gp(), result.gp());
#endif
      break;
    }
    case StoreType::kI64Store: {
#ifdef V8_TARGET_BIG_ENDIAN
      lrvgr(tmp1, expected.gp());
      lrvgr(tmp2, new_value.gp());
#else
      mov(tmp1, expected.gp());
      mov(tmp2, new_value.gp());
#endif
      CmpAndSwap64(tmp1, tmp2, MemOperand(ip));
      mov(result.gp(), tmp1);
#ifdef V8_TARGET_BIG_ENDIAN
      lrvgr(result.gp(), result.gp());
#endif
      break;
    }
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::AtomicFence() { bailout(kAtomics, "AtomicFence"); }

void LiftoffAssembler::LoadCallerFrameSlot(LiftoffRegister dst,
                                           uint32_t caller_slot_idx,
                                           ValueKind kind) {
  int32_t offset = (caller_slot_idx + 1) * 8;
  switch (kind) {
    case kI32: {
#if defined(V8_TARGET_BIG_ENDIAN)
      LoadS32(dst.gp(), MemOperand(fp, offset + 4));
      break;
#else
      LoadS32(dst.gp(), MemOperand(fp, offset));
      break;
#endif
    }
    case kRef:
    case kRtt:
    case kRefNull:
    case kI64: {
      LoadU64(dst.gp(), MemOperand(fp, offset));
      break;
    }
    case kF32: {
      LoadF32(dst.fp(), MemOperand(fp, offset));
      break;
    }
    case kF64: {
      LoadF64(dst.fp(), MemOperand(fp, offset));
      break;
    }
    case kS128: {
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      LoadV128(dst.fp(), MemOperand(fp, offset), scratch);
      break;
    }
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::StoreCallerFrameSlot(LiftoffRegister src,
                                            uint32_t caller_slot_idx,
                                            ValueKind kind,
                                            Register frame_pointer) {
  int32_t offset = (caller_slot_idx + 1) * 8;
  switch (kind) {
    case kI32: {
#if defined(V8_TARGET_BIG_ENDIAN)
      StoreU32(src.gp(), MemOperand(fp, offset + 4));
      break;
#else
      StoreU32(src.gp(), MemOperand(fp, offset));
      break;
#endif
    }
    case kRef:
    case kRtt:
    case kRefNull:
    case kI64: {
      StoreU64(src.gp(), MemOperand(fp, offset));
      break;
    }
    case kF32: {
      StoreF32(src.fp(), MemOperand(fp, offset));
      break;
    }
    case kF64: {
      StoreF64(src.fp(), MemOperand(fp, offset));
      break;
    }
    case kS128: {
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      StoreV128(src.fp(), MemOperand(fp, offset), scratch);
      break;
    }
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::LoadReturnStackSlot(LiftoffRegister dst, int offset,
                                           ValueKind kind) {
  switch (kind) {
    case kI32: {
#if defined(V8_TARGET_BIG_ENDIAN)
      LoadS32(dst.gp(), MemOperand(sp, offset + 4));
      break;
#else
      LoadS32(dst.gp(), MemOperand(sp, offset));
      break;
#endif
    }
    case kRef:
    case kRtt:
    case kRefNull:
    case kI64: {
      LoadU64(dst.gp(), MemOperand(sp, offset));
      break;
    }
    case kF32: {
      LoadF32(dst.fp(), MemOperand(sp, offset));
      break;
    }
    case kF64: {
      LoadF64(dst.fp(), MemOperand(sp, offset));
      break;
    }
    case kS128: {
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      LoadV128(dst.fp(), MemOperand(sp, offset), scratch);
      break;
    }
    default:
      UNREACHABLE();
  }
}

#ifdef V8_TARGET_BIG_ENDIAN
constexpr int stack_bias = -4;
#else
constexpr int stack_bias = 0;
#endif

void LiftoffAssembler::MoveStackValue(uint32_t dst_offset, uint32_t src_offset,
                                      ValueKind kind) {
  DCHECK_NE(dst_offset, src_offset);
  int length = 0;
  switch (kind) {
    case kI32:
    case kF32:
      length = 4;
      break;
    case kI64:
    case kRefNull:
    case kRef:
    case kRtt:
    case kF64:
      length = 8;
      break;
    case kS128:
      length = 16;
      break;
    default:
      UNREACHABLE();
  }

  dst_offset += (length == 4 ? stack_bias : 0);
  src_offset += (length == 4 ? stack_bias : 0);

  if (is_int20(dst_offset)) {
    lay(ip, liftoff::GetStackSlot(dst_offset));
  } else {
    mov(ip, Operand(-dst_offset));
    lay(ip, MemOperand(fp, ip));
  }

  if (is_int20(src_offset)) {
    lay(r1, liftoff::GetStackSlot(src_offset));
  } else {
    mov(r1, Operand(-src_offset));
    lay(r1, MemOperand(fp, r1));
  }

  MoveChar(MemOperand(ip), MemOperand(r1), Operand(length));
}

void LiftoffAssembler::Move(Register dst, Register src, ValueKind kind) {
  mov(dst, src);
}

void LiftoffAssembler::Move(DoubleRegister dst, DoubleRegister src,
                            ValueKind kind) {
  DCHECK_NE(dst, src);
  if (kind == kF32) {
    ler(dst, src);
  } else if (kind == kF64) {
    ldr(dst, src);
  } else {
    DCHECK_EQ(kS128, kind);
    vlr(dst, src, Condition(0), Condition(0), Condition(0));
  }
}

void LiftoffAssembler::Spill(int offset, LiftoffRegister reg, ValueKind kind) {
  DCHECK_LT(0, offset);
  RecordUsedSpillOffset(offset);

  switch (kind) {
    case kI32:
      StoreU32(reg.gp(), liftoff::GetStackSlot(offset + stack_bias));
      break;
    case kI64:
    case kRefNull:
    case kRef:
    case kRtt:
      StoreU64(reg.gp(), liftoff::GetStackSlot(offset));
      break;
    case kF32:
      StoreF32(reg.fp(), liftoff::GetStackSlot(offset + stack_bias));
      break;
    case kF64:
      StoreF64(reg.fp(), liftoff::GetStackSlot(offset));
      break;
    case kS128: {
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      StoreV128(reg.fp(), liftoff::GetStackSlot(offset), scratch);
      break;
    }
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::Spill(int offset, WasmValue value) {
  RecordUsedSpillOffset(offset);
  UseScratchRegisterScope temps(this);
  Register src = no_reg;
  src = ip;
  switch (value.type().kind()) {
    case kI32: {
      mov(src, Operand(value.to_i32()));
      StoreU32(src, liftoff::GetStackSlot(offset + stack_bias));
      break;
    }
    case kI64: {
      mov(src, Operand(value.to_i64()));
      StoreU64(src, liftoff::GetStackSlot(offset));
      break;
    }
    default:
      // We do not track f32 and f64 constants, hence they are unreachable.
      UNREACHABLE();
  }
}

void LiftoffAssembler::Fill(LiftoffRegister reg, int offset, ValueKind kind) {
  switch (kind) {
    case kI32:
      LoadS32(reg.gp(), liftoff::GetStackSlot(offset + stack_bias));
      break;
    case kI64:
    case kRef:
    case kRefNull:
    case kRtt:
      LoadU64(reg.gp(), liftoff::GetStackSlot(offset));
      break;
    case kF32:
      LoadF32(reg.fp(), liftoff::GetStackSlot(offset + stack_bias));
      break;
    case kF64:
      LoadF64(reg.fp(), liftoff::GetStackSlot(offset));
      break;
    case kS128: {
      UseScratchRegisterScope temps(this);
      Register scratch = temps.Acquire();
      LoadV128(reg.fp(), liftoff::GetStackSlot(offset), scratch);
      break;
    }
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::FillI64Half(Register, int offset, RegPairHalf) {
  UNREACHABLE();
}

void LiftoffAssembler::FillStackSlotsWithZero(int start, int size) {
  DCHECK_LT(0, size);
  DCHECK_EQ(0, size % 4);
  RecordUsedSpillOffset(start + size);

  // We need a zero reg. Always use r0 for that, and push it before to restore
  // its value afterwards.
  push(r0);
  mov(r0, Operand(0));

  if (size <= 5 * kStackSlotSize) {
    // Special straight-line code for up to five slots. Generates two
    // instructions per slot.
    uint32_t remainder = size;
    for (; remainder >= kStackSlotSize; remainder -= kStackSlotSize) {
      StoreU64(r0, liftoff::GetStackSlot(start + remainder));
    }
    DCHECK(remainder == 4 || remainder == 0);
    if (remainder) {
      StoreU32(r0, liftoff::GetStackSlot(start + remainder));
    }
  } else {
    // General case for bigger counts (9 instructions).
    // Use r3 for start address (inclusive), r4 for end address (exclusive).
    push(r3);
    push(r4);

    lay(r3, MemOperand(fp, -start - size));
    lay(r4, MemOperand(fp, -start));

    Label loop;
    bind(&loop);
    StoreU64(r0, MemOperand(r3));
    lay(r3, MemOperand(r3, kSystemPointerSize));
    CmpU64(r3, r4);
    bne(&loop);
    pop(r4);
    pop(r3);
  }

  pop(r0);
}

void LiftoffAssembler::LoadSpillAddress(Register dst, int offset,
                                        ValueKind kind) {
  if (kind == kI32) offset = offset + stack_bias;
  SubS64(dst, fp, Operand(offset));
}

#define SIGN_EXT(r) lgfr(r, r)
#define INT32_AND_WITH_1F(x) Operand(x & 0x1f)
#define REGISTER_AND_WITH_1F    \
  ([&](Register rhs) {          \
    AndP(r1, rhs, Operand(31)); \
    return r1;                  \
  })

#define LFR_TO_REG(reg) reg.gp()

// V(name, instr, dtype, stype, dcast, scast, rcast, return_val, return_type)
#define UNOP_LIST(V)                                                           \
  V(i32_popcnt, Popcnt32, Register, Register, , , USE, true, bool)             \
  V(i64_popcnt, Popcnt64, LiftoffRegister, LiftoffRegister, LFR_TO_REG,        \
    LFR_TO_REG, USE, true, bool)                                               \
  V(u32_to_uintptr, LoadU32, Register, Register, , , USE, , void)              \
  V(i32_signextend_i8, lbr, Register, Register, , , USE, , void)               \
  V(i32_signextend_i16, lhr, Register, Register, , , USE, , void)              \
  V(i64_signextend_i8, lgbr, LiftoffRegister, LiftoffRegister, LFR_TO_REG,     \
    LFR_TO_REG, USE, , void)                                                   \
  V(i64_signextend_i16, lghr, LiftoffRegister, LiftoffRegister, LFR_TO_REG,    \
    LFR_TO_REG, USE, , void)                                                   \
  V(i64_signextend_i32, LoadS32, LiftoffRegister, LiftoffRegister, LFR_TO_REG, \
    LFR_TO_REG, USE, , void)                                                   \
  V(i32_clz, CountLeadingZerosU32, Register, Register, , , USE, , void)        \
  V(i32_ctz, CountTrailingZerosU32, Register, Register, , , USE, , void)       \
  V(i64_clz, CountLeadingZerosU64, LiftoffRegister, LiftoffRegister,           \
    LFR_TO_REG, LFR_TO_REG, USE, , void)                                       \
  V(i64_ctz, CountTrailingZerosU64, LiftoffRegister, LiftoffRegister,          \
    LFR_TO_REG, LFR_TO_REG, USE, , void)                                       \
  V(f32_ceil, CeilF32, DoubleRegister, DoubleRegister, , , USE, true, bool)    \
  V(f32_floor, FloorF32, DoubleRegister, DoubleRegister, , , USE, true, bool)  \
  V(f32_trunc, TruncF32, DoubleRegister, DoubleRegister, , , USE, true, bool)  \
  V(f32_nearest_int, NearestIntF32, DoubleRegister, DoubleRegister, , , USE,   \
    true, bool)                                                                \
  V(f32_abs, lpebr, DoubleRegister, DoubleRegister, , , USE, , void)           \
  V(f32_neg, lcebr, DoubleRegister, DoubleRegister, , , USE, , void)           \
  V(f32_sqrt, sqebr, DoubleRegister, DoubleRegister, , , USE, , void)          \
  V(f64_ceil, CeilF64, DoubleRegister, DoubleRegister, , , USE, true, bool)    \
  V(f64_floor, FloorF64, DoubleRegister, DoubleRegister, , , USE, true, bool)  \
  V(f64_trunc, TruncF64, DoubleRegister, DoubleRegister, , , USE, true, bool)  \
  V(f64_nearest_int, NearestIntF64, DoubleRegister, DoubleRegister, , , USE,   \
    true, bool)                                                                \
  V(f64_abs, lpdbr, DoubleRegister, DoubleRegister, , , USE, , void)           \
  V(f64_neg, lcdbr, DoubleRegister, DoubleRegister, , , USE, , void)           \
  V(f64_sqrt, sqdbr, DoubleRegister, DoubleRegister, , , USE, , void)

#define EMIT_UNOP_FUNCTION(name, instr, dtype, stype, dcast, scast, rcast, \
                           ret, return_type)                               \
  return_type LiftoffAssembler::emit_##name(dtype dst, stype src) {        \
    auto _dst = dcast(dst);                                                \
    auto _src = scast(src);                                                \
    instr(_dst, _src);                                                     \
    rcast(_dst);                                                           \
    return ret;                                                            \
  }
UNOP_LIST(EMIT_UNOP_FUNCTION)
#undef EMIT_UNOP_FUNCTION
#undef UNOP_LIST

// V(name, instr, dtype, stype1, stype2, dcast, scast1, scast2, rcast,
// return_val, return_type)
#define BINOP_LIST(V)                                                          \
  V(f32_min, FloatMin, DoubleRegister, DoubleRegister, DoubleRegister, , , ,   \
    USE, , void)                                                               \
  V(f32_max, FloatMax, DoubleRegister, DoubleRegister, DoubleRegister, , , ,   \
    USE, , void)                                                               \
  V(f64_min, DoubleMin, DoubleRegister, DoubleRegister, DoubleRegister, , , ,  \
    USE, , void)                                                               \
  V(f64_max, DoubleMax, DoubleRegister, DoubleRegister, DoubleRegister, , , ,  \
    USE, , void)                                                               \
  V(f64_add, AddF64, DoubleRegister, DoubleRegister, DoubleRegister, , , ,     \
    USE, , void)                                                               \
  V(f64_sub, SubF64, DoubleRegister, DoubleRegister, DoubleRegister, , , ,     \
    USE, , void)                                                               \
  V(f64_mul, MulF64, DoubleRegister, DoubleRegister, DoubleRegister, , , ,     \
    USE, , void)                                                               \
  V(f64_div, DivF64, DoubleRegister, DoubleRegister, DoubleRegister, , , ,     \
    USE, , void)                                                               \
  V(f32_add, AddF32, DoubleRegister, DoubleRegister, DoubleRegister, , , ,     \
    USE, , void)                                                               \
  V(f32_sub, SubF32, DoubleRegister, DoubleRegister, DoubleRegister, , , ,     \
    USE, , void)                                                               \
  V(f32_mul, MulF32, DoubleRegister, DoubleRegister, DoubleRegister, , , ,     \
    USE, , void)                                                               \
  V(f32_div, DivF32, DoubleRegister, DoubleRegister, DoubleRegister, , , ,     \
    USE, , void)                                                               \
  V(i32_shli, ShiftLeftU32, Register, Register, int32_t, , ,                   \
    INT32_AND_WITH_1F, SIGN_EXT, , void)                                       \
  V(i32_sari, ShiftRightS32, Register, Register, int32_t, , ,                  \
    INT32_AND_WITH_1F, SIGN_EXT, , void)                                       \
  V(i32_shri, ShiftRightU32, Register, Register, int32_t, , ,                  \
    INT32_AND_WITH_1F, SIGN_EXT, , void)                                       \
  V(i32_shl, ShiftLeftU32, Register, Register, Register, , ,                   \
    REGISTER_AND_WITH_1F, SIGN_EXT, , void)                                    \
  V(i32_sar, ShiftRightS32, Register, Register, Register, , ,                  \
    REGISTER_AND_WITH_1F, SIGN_EXT, , void)                                    \
  V(i32_shr, ShiftRightU32, Register, Register, Register, , ,                  \
    REGISTER_AND_WITH_1F, SIGN_EXT, , void)                                    \
  V(i32_addi, AddS32, Register, Register, int32_t, , , Operand, SIGN_EXT, ,    \
    void)                                                                      \
  V(i32_subi, SubS32, Register, Register, int32_t, , , Operand, SIGN_EXT, ,    \
    void)                                                                      \
  V(i32_andi, And, Register, Register, int32_t, , , Operand, SIGN_EXT, , void) \
  V(i32_ori, Or, Register, Register, int32_t, , , Operand, SIGN_EXT, , void)   \
  V(i32_xori, Xor, Register, Register, int32_t, , , Operand, SIGN_EXT, , void) \
  V(i32_add, AddS32, Register, Register, Register, , , , SIGN_EXT, , void)     \
  V(i32_sub, SubS32, Register, Register, Register, , , , SIGN_EXT, , void)     \
  V(i32_and, And, Register, Register, Register, , , , SIGN_EXT, , void)        \
  V(i32_or, Or, Register, Register, Register, , , , SIGN_EXT, , void)          \
  V(i32_xor, Xor, Register, Register, Register, , , , SIGN_EXT, , void)        \
  V(i32_mul, MulS32, Register, Register, Register, , , , SIGN_EXT, , void)     \
  V(i64_add, AddS64, LiftoffRegister, LiftoffRegister, LiftoffRegister,        \
    LFR_TO_REG, LFR_TO_REG, LFR_TO_REG, USE, , void)                           \
  V(i64_sub, SubS64, LiftoffRegister, LiftoffRegister, LiftoffRegister,        \
    LFR_TO_REG, LFR_TO_REG, LFR_TO_REG, USE, , void)                           \
  V(i64_mul, MulS64, LiftoffRegister, LiftoffRegister, LiftoffRegister,        \
    LFR_TO_REG, LFR_TO_REG, LFR_TO_REG, USE, , void)                           \
  V(i64_and, AndP, LiftoffRegister, LiftoffRegister, LiftoffRegister,          \
    LFR_TO_REG, LFR_TO_REG, LFR_TO_REG, USE, , void)                           \
  V(i64_or, OrP, LiftoffRegister, LiftoffRegister, LiftoffRegister,            \
    LFR_TO_REG, LFR_TO_REG, LFR_TO_REG, USE, , void)                           \
  V(i64_xor, XorP, LiftoffRegister, LiftoffRegister, LiftoffRegister,          \
    LFR_TO_REG, LFR_TO_REG, LFR_TO_REG, USE, , void)                           \
  V(i64_shl, ShiftLeftU64, LiftoffRegister, LiftoffRegister, Register,         \
    LFR_TO_REG, LFR_TO_REG, , USE, , void)                                     \
  V(i64_sar, ShiftRightS64, LiftoffRegister, LiftoffRegister, Register,        \
    LFR_TO_REG, LFR_TO_REG, , USE, , void)                                     \
  V(i64_shr, ShiftRightU64, LiftoffRegister, LiftoffRegister, Register,        \
    LFR_TO_REG, LFR_TO_REG, , USE, , void)                                     \
  V(i64_addi, AddS64, LiftoffRegister, LiftoffRegister, int64_t, LFR_TO_REG,   \
    LFR_TO_REG, Operand, USE, , void)                                          \
  V(i64_andi, AndP, LiftoffRegister, LiftoffRegister, int32_t, LFR_TO_REG,     \
    LFR_TO_REG, Operand, USE, , void)                                          \
  V(i64_ori, OrP, LiftoffRegister, LiftoffRegister, int32_t, LFR_TO_REG,       \
    LFR_TO_REG, Operand, USE, , void)                                          \
  V(i64_xori, XorP, LiftoffRegister, LiftoffRegister, int32_t, LFR_TO_REG,     \
    LFR_TO_REG, Operand, USE, , void)                                          \
  V(i64_shli, ShiftLeftU64, LiftoffRegister, LiftoffRegister, int32_t,         \
    LFR_TO_REG, LFR_TO_REG, Operand, USE, , void)                              \
  V(i64_sari, ShiftRightS64, LiftoffRegister, LiftoffRegister, int32_t,        \
    LFR_TO_REG, LFR_TO_REG, Operand, USE, , void)                              \
  V(i64_shri, ShiftRightU64, LiftoffRegister, LiftoffRegister, int32_t,        \
    LFR_TO_REG, LFR_TO_REG, Operand, USE, , void)

#define EMIT_BINOP_FUNCTION(name, instr, dtype, stype1, stype2, dcast, scast1, \
                            scast2, rcast, ret, return_type)                   \
  return_type LiftoffAssembler::emit_##name(dtype dst, stype1 lhs,             \
                                            stype2 rhs) {                      \
    auto _dst = dcast(dst);                                                    \
    auto _lhs = scast1(lhs);                                                   \
    auto _rhs = scast2(rhs);                                                   \
    instr(_dst, _lhs, _rhs);                                                   \
    rcast(_dst);                                                               \
    return ret;                                                                \
  }

BINOP_LIST(EMIT_BINOP_FUNCTION)
#undef BINOP_LIST
#undef EMIT_BINOP_FUNCTION
#undef SIGN_EXT
#undef INT32_AND_WITH_1F
#undef REGISTER_AND_WITH_1F
#undef LFR_TO_REG

void LiftoffAssembler::IncrementSmi(LiftoffRegister dst, int offset) {
  UseScratchRegisterScope temps(this);
  if (COMPRESS_POINTERS_BOOL) {
    DCHECK(SmiValuesAre31Bits());
    Register scratch = temps.Acquire();
    LoadS32(scratch, MemOperand(dst.gp(), offset));
    AddU32(scratch, Operand(Smi::FromInt(1)));
    StoreU32(scratch, MemOperand(dst.gp(), offset));
  } else {
    Register scratch = temps.Acquire();
    SmiUntag(scratch, MemOperand(dst.gp(), offset));
    AddU64(scratch, Operand(1));
    SmiTag(scratch);
    StoreU64(scratch, MemOperand(dst.gp(), offset));
  }
}

void LiftoffAssembler::emit_i32_divs(Register dst, Register lhs, Register rhs,
                                     Label* trap_div_by_zero,
                                     Label* trap_div_unrepresentable) {
  Label cont;

  // Check for division by zero.
  ltr(r0, rhs);
  b(eq, trap_div_by_zero);

  // Check for kMinInt / -1. This is unrepresentable.
  CmpS32(rhs, Operand(-1));
  bne(&cont);
  CmpS32(lhs, Operand(kMinInt));
  b(eq, trap_div_unrepresentable);

  bind(&cont);
  DivS32(dst, lhs, rhs);
}

void LiftoffAssembler::emit_i32_divu(Register dst, Register lhs, Register rhs,
                                     Label* trap_div_by_zero) {
  // Check for division by zero.
  ltr(r0, rhs);
  beq(trap_div_by_zero);
  DivU32(dst, lhs, rhs);
}

void LiftoffAssembler::emit_i32_rems(Register dst, Register lhs, Register rhs,
                                     Label* trap_div_by_zero) {
  Label cont;
  Label done;
  Label trap_div_unrepresentable;
  // Check for division by zero.
  ltr(r0, rhs);
  beq(trap_div_by_zero);

  // Check kMinInt/-1 case.
  CmpS32(rhs, Operand(-1));
  bne(&cont);
  CmpS32(lhs, Operand(kMinInt));
  beq(&trap_div_unrepresentable);

  // Continue noraml calculation.
  bind(&cont);
  ModS32(dst, lhs, rhs);
  bne(&done);

  // trap by kMinInt/-1 case.
  bind(&trap_div_unrepresentable);
  mov(dst, Operand(0));
  bind(&done);
}

void LiftoffAssembler::emit_i32_remu(Register dst, Register lhs, Register rhs,
                                     Label* trap_div_by_zero) {
  // Check for division by zero.
  ltr(r0, rhs);
  beq(trap_div_by_zero);
  ModU32(dst, lhs, rhs);
}

bool LiftoffAssembler::emit_i64_divs(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs,
                                     Label* trap_div_by_zero,
                                     Label* trap_div_unrepresentable) {
  // Use r0 to check for kMinInt / -1.
  constexpr int64_t kMinInt64 = static_cast<int64_t>(1) << 63;
  Label cont;
  // Check for division by zero.
  ltgr(r0, rhs.gp());
  beq(trap_div_by_zero);

  // Check for kMinInt / -1. This is unrepresentable.
  CmpS64(rhs.gp(), Operand(-1));
  bne(&cont);
  mov(r0, Operand(kMinInt64));
  CmpS64(lhs.gp(), r0);
  b(eq, trap_div_unrepresentable);

  bind(&cont);
  DivS64(dst.gp(), lhs.gp(), rhs.gp());
  return true;
}

bool LiftoffAssembler::emit_i64_divu(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs,
                                     Label* trap_div_by_zero) {
  ltgr(r0, rhs.gp());
  b(eq, trap_div_by_zero);
  // Do div.
  DivU64(dst.gp(), lhs.gp(), rhs.gp());
  return true;
}

bool LiftoffAssembler::emit_i64_rems(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs,
                                     Label* trap_div_by_zero) {
  constexpr int64_t kMinInt64 = static_cast<int64_t>(1) << 63;

  Label trap_div_unrepresentable;
  Label done;
  Label cont;

  // Check for division by zero.
  ltgr(r0, rhs.gp());
  beq(trap_div_by_zero);

  // Check for kMinInt / -1. This is unrepresentable.
  CmpS64(rhs.gp(), Operand(-1));
  bne(&cont);
  mov(r0, Operand(kMinInt64));
  CmpS64(lhs.gp(), r0);
  beq(&trap_div_unrepresentable);

  bind(&cont);
  ModS64(dst.gp(), lhs.gp(), rhs.gp());
  bne(&done);

  bind(&trap_div_unrepresentable);
  mov(dst.gp(), Operand(0));
  bind(&done);
  return true;
}

bool LiftoffAssembler::emit_i64_remu(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs,
                                     Label* trap_div_by_zero) {
  // Check for division by zero.
  ltgr(r0, rhs.gp());
  beq(trap_div_by_zero);
  ModU64(dst.gp(), lhs.gp(), rhs.gp());
  return true;
}

void LiftoffAssembler::emit_f32_copysign(DoubleRegister dst, DoubleRegister lhs,
                                         DoubleRegister rhs) {
  constexpr uint64_t kF64SignBit = uint64_t{1} << 63;
  UseScratchRegisterScope temps(this);
  Register scratch2 = temps.Acquire();
  MovDoubleToInt64(r0, lhs);
  // Clear sign bit in {r0}.
  AndP(r0, Operand(~kF64SignBit));

  MovDoubleToInt64(scratch2, rhs);
  // Isolate sign bit in {scratch2}.
  AndP(scratch2, Operand(kF64SignBit));
  // Combine {scratch2} into {r0}.
  OrP(r0, r0, scratch2);
  MovInt64ToDouble(dst, r0);
}

void LiftoffAssembler::emit_f64_copysign(DoubleRegister dst, DoubleRegister lhs,
                                         DoubleRegister rhs) {
  constexpr uint64_t kF64SignBit = uint64_t{1} << 63;
  UseScratchRegisterScope temps(this);
  Register scratch2 = temps.Acquire();
  MovDoubleToInt64(r0, lhs);
  // Clear sign bit in {r0}.
  AndP(r0, Operand(~kF64SignBit));

  MovDoubleToInt64(scratch2, rhs);
  // Isolate sign bit in {scratch2}.
  AndP(scratch2, Operand(kF64SignBit));
  // Combine {scratch2} into {r0}.
  OrP(r0, r0, scratch2);
  MovInt64ToDouble(dst, r0);
}

bool LiftoffAssembler::emit_type_conversion(WasmOpcode opcode,
                                            LiftoffRegister dst,
                                            LiftoffRegister src, Label* trap) {
  switch (opcode) {
    case kExprI32ConvertI64:
      lgfr(dst.gp(), src.gp());
      return true;
    case kExprI32SConvertF32: {
      ConvertFloat32ToInt32(dst.gp(), src.fp(),
                            kRoundToZero);  // f32 -> i32 round to zero.
      b(Condition(1), trap);
      return true;
    }
    case kExprI32UConvertF32: {
      ConvertFloat32ToUnsignedInt32(dst.gp(), src.fp(), kRoundToZero);
      b(Condition(1), trap);
      return true;
    }
    case kExprI32SConvertF64: {
      ConvertDoubleToInt32(dst.gp(), src.fp());
      b(Condition(1), trap);
      return true;
    }
    case kExprI32UConvertF64: {
      ConvertDoubleToUnsignedInt32(dst.gp(), src.fp(), kRoundToZero);
      b(Condition(1), trap);
      return true;
    }
    
"""


```